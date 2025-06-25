import express from 'express';
import cors from 'cors';
import {db, generatePayload} from "./payload";
import {TonProof} from "./models";
import {checkProof} from "./proof";
import * as jsonwebtoken from 'jsonwebtoken';
import {NextFunction, Request, Response} from "express";
import {tonapi} from "./tonapi";
import * as crypto from 'crypto';
import * as dotenv from 'dotenv';
import * as fs from 'fs';
import * as path from 'path';
import { address, Address } from "@ton/core";
import { Pool } from 'pg';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();
app.set('trust proxy', process.env.NODE_ENV === 'production' ? 1 : false);
app.use(cors());
app.use(express.json());

const backendSecret = process.env.BACKEND_SECRET || 'MY_SECRET_FROM_ENV';
const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173'; 
const musicBackendUrl = process.env.MUSIC_BACKEND_URL || 'http://localhost:8000';

const recreatePayloadFrequency = 1000 * 60 * 10;

const whitelistPath = path.join(__dirname, 'whitelist.json');
const whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')).collections;

// Rate limiters
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100, // Лимит для каждого IP
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Слишком много запросов, попробуйте позже',
  skip: (req) => {
    // Пропускаем лимит для health-check эндпоинтов
    return req.path === '/health' || req.path === '/';
  }
});

const strictLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 час
  max: 10, // Строгий лимит для важных эндпоинтов
  message: 'Слишком много запросов к защищенным эндпоинтам'
});

const keysLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 минут
  max: 20, // Лимит для генерации ключей
  message: 'Слишком много запросов к защищенным эндпоинтам'
});

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false
});

// Global sync status tracking
let lastSyncTime: Date | null = null;
let syncInProgress = false;

// Database initialization and sync functions
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create tables if they don't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS collections (
        address VARCHAR(200) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        image TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS nfts (
        address VARCHAR(200) PRIMARY KEY,
        collection_address VARCHAR(200) REFERENCES collections(address),
        index_number INTEGER,
        metadata JSONB DEFAULT '{}',
        first_listen TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS listens (
        id SERIAL PRIMARY KEY,
        nft_address VARCHAR(200) REFERENCES nfts(address),
        collection_address VARCHAR(200) REFERENCES collections(address),
        count INTEGER DEFAULT 1,
        last_updated TIMESTAMP DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(nft_address)
      )
    `);

    // Добавляем таблицу для API ключей (которая используется в коде, но не создается)
    await client.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        key VARCHAR(255) PRIMARY KEY,
        address VARCHAR(200) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL
      )
    `);

    // Create indexes for optimization
    await client.query(`CREATE INDEX IF NOT EXISTS idx_listens_nft_address ON listens(nft_address)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_listens_collection_address ON listens(collection_address)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_listens_count ON listens(count DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_nfts_collection_address ON nfts(collection_address)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_nfts_index ON nfts(index_number)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_collections_address ON collections(address)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_api_keys_address ON api_keys(address)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at)`);

    await client.query('COMMIT');
    console.log('✅ База данных инициализирована');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ Ошибка инициализации базы данных:', error);
    throw error;
  } finally {
    client.release();
  }
}

async function syncCollectionsFromWhitelist() {
  console.log('🔄 Синхронизация коллекций из whitelist...');
  let syncedCount = 0;
  
  for (let collectionAddressString of whitelist) {
    try {
      // Parse address to validate format
      const parsedAddress = Address.parse(collectionAddressString).toString();
      const collectionAddress = parsedAddress.toString(); // Convert back to string for database
      
      // Get collection info from TON API
      const collectionInfo = await tonapi.nft.getNftCollection(parsedAddress);
      
      const client = await pool.connect();
      try {
        await client.query(`
          INSERT INTO collections (address, name, image, description, updated_at)
          VALUES ($1, $2, $3, $4, NOW())
          ON CONFLICT (address) 
          DO UPDATE SET 
            name = EXCLUDED.name,
            image = EXCLUDED.image,
            description = EXCLUDED.description,
            updated_at = NOW()
        `, [
          collectionAddress,
          collectionInfo.metadata?.name || `Collection ${collectionAddress.slice(-6)}`,
          collectionInfo.metadata?.image || null,
          collectionInfo.metadata?.description || null
        ]);
        
        syncedCount++;
        console.log(`✅ Коллекция синхронизирована: ${collectionInfo.metadata?.name || collectionAddress}`);
      } catch (dbError) {
        console.error(`❌ Ошибка сохранения коллекции ${collectionAddress}:`, dbError);
      } finally {
        client.release();
      }
    } catch (apiError) {
      console.error(`⚠️ Ошибка получения данных коллекции ${collectionAddressString}:`, apiError);
      
      // If we can't get data from API, create basic record
      const client = await pool.connect();
      try {
        // Parse address for basic record too
        const parsedAddress = Address.parse(collectionAddressString);
        const collectionAddress = parsedAddress.toString();
        
        await client.query(`
          INSERT INTO collections (address, name, description, updated_at)
          VALUES ($1, $2, $3, NOW())
          ON CONFLICT (address) DO UPDATE SET updated_at = NOW()
        `, [
          collectionAddress,
          `Collection ${collectionAddress.slice(-6)}`,
          'NFT коллекция'
        ]);
        syncedCount++;
        console.log(`✅ Создана базовая запись для коллекции: ${collectionAddress}`);
      } catch (dbError) {
        console.error(`❌ Ошибка создания базовой записи коллекции ${collectionAddressString}:`, dbError);
      } finally {
        client.release();
      }
    }

    // Small delay between requests to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  
  console.log(`✅ Синхронизировано ${syncedCount} коллекций`);
}

async function syncNFTsFromCollection(collectionAddress: string, limit: number = 100) {
  console.log(`🔄 Синхронизация NFT для коллекции ${collectionAddress}...`);
  
  try {
    // Поскольку прямого метода получения NFT из коллекции может не быть,
    // мы будем полагаться на данные, которые приходят при запросах пользователей
    // и создадим базовые записи для коллекции
    
    const client = await pool.connect();
    try {
      // Создаем базовую запись коллекции если её нет
      await client.query(`
        INSERT INTO collections (address, name, description, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (address) DO UPDATE SET updated_at = NOW()
      `, [
        collectionAddress,
        `Collection ${collectionAddress.slice(-6)}`,
        'NFT коллекция из whitelist'
      ]);
      
      console.log(`✅ Базовая запись создана для коллекции ${collectionAddress}`);
    } finally {
      client.release();
    }
    
    console.log(`ℹ️ NFT будут добавлены в базу данных при первых прослушиваниях`);
  } catch (error) {
    console.error(`❌ Ошибка создания базовой записи для коллекции ${collectionAddress}:`, error);
  }
}

async function performFullSync() {
  if (syncInProgress) {
    console.log('⏳ Синхронизация уже выполняется, пропускаем...');
    return;
  }

  syncInProgress = true;
  console.log('🚀 Начинаем полную синхронизацию данных...');
  
  try {
    // First sync collections
    await syncCollectionsFromWhitelist();
    
    // Then sync NFTs for each collection
    for (const collectionAddress of whitelist) {
      await syncNFTsFromCollection(collectionAddress, 200); // Limit NFTs per collection
      // Pause between collections
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    lastSyncTime = new Date();
    console.log('✅ Полная синхронизация завершена успешно');
  } catch (error) {
    console.error('❌ Ошибка при полной синхронизации:', error);
  } finally {
    syncInProgress = false;
  }
}

// API Key management functions
async function saveApiKey(apiKey: string, address: string, created: Date, expires: Date) {
  const client = await pool.connect();
  address = Address.parse(address).toString();
  try {
    await client.query('BEGIN');
    
    // Delete old user keys (including expired ones)
    await client.query(
      'DELETE FROM api_keys WHERE address = $1 OR expires_at < NOW()',
      [address]
    );
    
    // Create new key
    await client.query(
      'INSERT INTO api_keys (key, address, created_at, expires_at) VALUES ($1, $2, $3, $4)',
      [apiKey, address, created, expires]
    );
    
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function validateApiKey(apiKey: string) {
  const result = await pool.query('SELECT * FROM api_keys WHERE key = $1', [apiKey]);
  const keyData = result.rows[0];
  if (!keyData || new Date() > new Date(keyData.expires_at)) {
    if (keyData) await pool.query('DELETE FROM api_keys WHERE key = $1', [apiKey]);
    return null;
  }
  return { address: keyData.address, expires: new Date(keyData.expires_at) };
}

// Middleware
async function checkJWT(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization?.split('Bearer ')[1];

    if (!token) {
        res.sendStatus(401);
        return;
    }

    jsonwebtoken.verify(token, backendSecret, (err, decoded) => {
        if (err) {
            res.sendStatus(401);
        }

        (req as unknown as { userAddress: string }).userAddress = decoded as string;

        next();
    })
}

// Apply rate limiters
app.use(apiLimiter);

// TON Proof endpoints
app.post('/ton-proof/generatePayload', keysLimiter, (req, res) => {
    const payload = generatePayload();
    db.payloads.push(payload);

    setTimeout(() => {
        db.payloads = db.payloads.filter(p => p !== payload);
    }, recreatePayloadFrequency);

    res.json({payload});
})

app.post('/ton-proof/checkProof', strictLimiter, async (req, res) => {
    const tonProof = req.body as TonProof;
    const isValid = await checkProof(tonProof)

    if (isValid) {
        const token = jsonwebtoken.sign(tonProof.address, backendSecret);
        res.json({token});
    } else {
        res.status(400).send('Wrong proof');
    }
})

// Protected endpoints
app.post('/dapp/generateMusicApiKey', keysLimiter, checkJWT, async (req, res) => {
    try {
        const userAddress = (req as unknown as { userAddress: string }).userAddress;
        
        const apiKey = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
        
        await saveApiKey(apiKey, userAddress, new Date(), expiresAt);
        
        res.json({
            apiKey,
            expiresAt: expiresAt.toISOString(),
            musicServerUrl: musicBackendUrl
        });
        
    } catch (error) {
        console.error('Ошибка при генерации API ключа:', error);
        res.status(500).json({ error: 'Ошибка генерации API ключа' });
    }
})

app.post('/api/validateMusicApiKey', async (req, res) => {
    try {
        const { apiKey } = req.body;
        
        if (!apiKey) {
            return res.status(400).json({ valid: false, error: 'API ключ не предоставлен' });
        }
        
        const keyData = await validateApiKey(apiKey);
        
        if (!keyData) {
            return res.status(401).json({ valid: false, error: 'Недействительный или истекший API ключ' });
        }
        
        res.json({
            valid: true,
            address: keyData.address,
            expiresAt: keyData.expires.toISOString()
        });
        
    } catch (error) {
        console.error('Ошибка при проверке API ключа:', error);
        res.status(500).json({ valid: false, error: 'Ошибка сервера' });
    }
});

app.get('/dapp/getAccountInfo', strictLimiter, checkJWT, async (req, res) => {
    res.json({ address: (req as unknown as { userAddress: string }).userAddress });
})

app.get('/dapp/getNFTs', strictLimiter, checkJWT, async (req, res) => {
    try {
        const userAddress = (req as unknown as { userAddress: string }).userAddress;
        const { network = 'mainnet', limit = 100, offset = 0 } = req.query;

        if (req.query.walletAddress && req.query.walletAddress !== userAddress) {
            return res.status(403).json({ error: 'Нет доступа к NFT этого адреса' });
        }

        const nftItems = await tonapi.accounts.getAccountNftItems(
            userAddress,
            {
                limit: parseInt(limit as string),
                offset: parseInt(offset as string),
                indirect_ownership: false
            }
        );

        const filteredNfts = nftItems.nft_items.filter(nft => {                
            if (!nft.collection) return false;
            return whitelist.includes(Address.parse(nft.collection.address).toString());
        });

        const formattedNfts = filteredNfts.map(nft => ({
            address: nft.address,
            index: nft.index,
            metadata: {
                name: nft.metadata?.name || 'Unnamed NFT',
                image: nft.metadata?.image,
                description: nft.metadata?.description,
                ...nft.metadata
            },
            collection: nft.collection ? {
                name: nft.collection.name,
                address: nft.collection.address
            } : undefined,                
            trust: nft.metadata.trust,
            audioUrl: nft.metadata?.audioUrl                
        }));

        res.json({
            data: {
                nft_items: formattedNfts
            },
            total: formattedNfts.length,
            hasMore: nftItems.nft_items.length === parseInt(limit as string)
        });

    } catch (error) {
        console.error('Ошибка при получении NFT:', error);
        res.status(500).json({ 
            error: 'Ошибка при загрузке NFT',
            details: error instanceof Error ? error.message : 'Неизвестная ошибка'
        });
    }
})

// Public API endpoints for collections and listens
app.get('/api/collections', async (req, res) => {
    try {
        // Get collection statistics from database
        const collectionsQuery = `
            SELECT 
                c.address,
                c.name,
                c.image,
                c.description,
                COALESCE(SUM(l.count), 0) as total_listens
            FROM collections c
            LEFT JOIN listens l ON c.address = l.collection_address
            WHERE c.address = ANY($1)
            GROUP BY c.address, c.name, c.image, c.description
            ORDER BY total_listens DESC
        `;
        
        const result = await pool.query(collectionsQuery, [whitelist]);
        
        const collections = result.rows.map(row => ({
            address: row.address,
            name: row.name,
            image: row.image,
            description: row.description,
            totalListens: parseInt(row.total_listens) || 0
        }));

        res.json({ collections });
        
    } catch (error) {
        console.error('Ошибка при получении коллекций:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/collections/:address/top-nfts', async (req, res) => {
    try {
        const { address } = req.params;
        const limit = parseInt(req.query.limit as string) || 7;

        // Проверяем, что коллекция в whitelist
        if (!whitelist.includes(address)) {
            return res.status(404).json({ error: 'Коллекция не найдена' });
        }

        // Получаем только топ NFT с прослушиваниями больше 0
        const topNftsQuery = `
            SELECT 
                n.address,
                n.index_number as index,
                n.metadata,
                n.collection_address,
                c.name as collection_name,
                COALESCE(l.count, 0) as listens
            FROM nfts n
            LEFT JOIN listens l ON n.address = l.nft_address
            LEFT JOIN collections c ON n.collection_address = c.address
            WHERE n.collection_address = $1 AND COALESCE(l.count, 0) > 0
            ORDER BY listens DESC, n.index_number ASC
            LIMIT $2
        `;

        const result = await pool.query(topNftsQuery, [address, limit]);
        
        const nfts = result.rows.map(row => ({
            address: row.address,
            index: row.index,
            metadata: row.metadata || {},
            collection: {
                name: row.collection_name,
                address: row.collection_address
            },
            listens: parseInt(row.listens) || 0
        }));

        res.json({ nfts });
        
    } catch (error) {
        console.error('Ошибка при получении топ NFT:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/collections/:address/nfts-stats', async (req, res) => {
    try {
        const { address } = req.params;
        const limit = parseInt(req.query.limit as string) || 100;
        const offset = parseInt(req.query.offset as string) || 0;

        // Проверяем, что коллекция в whitelist
        if (!whitelist.includes(address)) {
            return res.status(404).json({ error: 'Коллекция не найдена в whitelist' });
        }

        console.log('📊 Получаем все NFT коллекции со статистикой:', {
            collectionAddress: address,
            limit,
            offset
        });

        const client = await pool.connect();
        try {
            // Получаем NFT из базы данных
            const dbNftsQuery = `
                SELECT 
                    n.address,
                    n.index_number as index,
                    n.metadata,
                    n.collection_address,
                    c.name as collection_name,
                    COALESCE(l.count, 0) as listens
                FROM nfts n
                LEFT JOIN listens l ON n.address = l.nft_address
                LEFT JOIN collections c ON n.collection_address = c.address
                WHERE n.collection_address = $1
                ORDER BY listens DESC, n.index_number ASC
                LIMIT $2 OFFSET $3
            `;

            const dbResult = await client.query(dbNftsQuery, [address, limit, offset]);
            let nfts = dbResult.rows;

            console.log('🔍 NFT найдено в базе данных:', nfts.length);

            // Если в базе мало NFT, дополняем из TON API
            if (nfts.length < 10) {
                try {
                    console.log('🌐 Загружаем дополнительные NFT из TON API...');
                    
                    const collectionInfo = await tonapi.nft.getNftCollection(address);
                    let apiNfts: any[] = [];
                    try {
                        const nftItems = await tonapi.nft.getItemsFromCollection(address, {
                            limit: Math.max(50, limit),
                            offset: 0
                        });
                        apiNfts = nftItems.nft_items || [];
                    } catch (apiError) {
                        console.log('⚠️ Не удалось получить NFT через getItemsFromCollection');
                    }

                    console.log('📡 Получено NFT из API:', apiNfts.length);

                    // Создаем Map для исключения дубликатов
                    const nftMap = new Map<string, any>();

                    // Сначала добавляем NFT из базы данных
                    nfts.forEach(nft => {
                        nftMap.set(nft.address, {
                            address: nft.address,
                            index: nft.index,
                            metadata: nft.metadata,
                            collection_address: address,
                            collection_name: collectionInfo.metadata?.name || 'Неизвестная коллекция',
                            listens: parseInt(nft.listens) || 0
                        });
                    });

                    // Добавляем только новые NFT из API
                    apiNfts.forEach(apiNft => {
                        let nftAddress = apiNft.address || `api-index-${apiNft.index || Math.random().toString(36).slice(2)}`;
                        nftAddress = Address.parse(nftAddress).toString();

                        if (!apiNft.address) {
                            console.warn('⚠️ NFT без адреса:', apiNft);
                            return; // Пропускаем такие NFT
                        }

                        if (nftMap.has(nftAddress)) {
                            console.log('🔍 Обнаружен дубликат:', nftAddress);
                        }
                        
                        if (!nftMap.has(nftAddress)) {
                            nftMap.set(nftAddress, {
                                address: Address.parse(apiNft.address).toString() || '',
                                index: apiNft.index || 0,
                                metadata: apiNft.metadata || {},
                                collection_address: address,
                                collection_name: collectionInfo.metadata?.name || 'Неизвестная коллекция',
                                listens: 0
                            });
                        }
                    });

                    nfts = Array.from(nftMap.values());

                } catch (apiError) {
                    console.error('❌ Ошибка получения NFT из TON API:', apiError);
                }
            }

            // Сортируем по количеству прослушиваний и индексу
            nfts.sort((a, b) => {
                const listensA = parseInt(a.listens) || 0;
                const listensB = parseInt(b.listens) || 0;
                if (listensA !== listensB) {
                    return listensB - listensA;
                }
                const indexA = a.index || 0;
                const indexB = b.index || 0;
                return indexA - indexB;
            });

            // Применяем пагинацию
            const paginatedNfts = nfts.slice(offset, offset + limit);

            // Форматируем ответ
            const formattedNfts = paginatedNfts.map(nft => ({
                address: nft.address,
                index: nft.index,
                metadata: typeof nft.metadata === 'string' ? JSON.parse(nft.metadata) : nft.metadata,
                collection: {
                    name: nft.collection_name,
                    address: nft.collection_address
                },
                listens: parseInt(nft.listens) || 0
            }));

            console.log('✅ Статистика коллекции сформирована:', {
                totalFound: nfts.length,
                returned: formattedNfts.length,
                withListens: formattedNfts.filter(n => n.listens > 0).length,
                withoutListens: formattedNfts.filter(n => n.listens === 0).length
            });

            res.json({ 
                nfts: formattedNfts,
                total: nfts.length,
                hasMore: (offset + limit) < nfts.length
            });

        } finally {
            client.release();
        }
        
    } catch (error) {
        console.error('❌ Ошибка при получении статистики коллекции:', error);
        res.status(500).json({ 
            error: 'Ошибка сервера при получении статистики',
            details: error instanceof Error ? error.message : 'Неизвестная ошибка'
        });
    }
});

app.post('/api/listens', async (req, res) => {
    try {
        const { nftAddress, collectionAddress } = req.body;

        console.log('📊 Получен запрос на запись прослушивания:', {
            nftAddress,
            collectionAddress,
            timestamp: new Date().toISOString()
        });

        if (!nftAddress || !collectionAddress) {
            console.warn('❌ Отсутствуют обязательные параметры:', {
                hasNftAddress: !!nftAddress,
                hasCollectionAddress: !!collectionAddress
            });
            return res.status(400).json({ 
                error: 'Необходимы nftAddress и collectionAddress' 
            });
        }

        // Нормализуем адреса - приводим к стандартному формату
        let normalizedNftAddress: string;
        let normalizedCollectionAddress: string;

        try {
            // Парсим и нормализуем адрес NFT
            const parsedNftAddress = Address.parse(nftAddress);
            normalizedNftAddress = parsedNftAddress.toString();

            // Парсим и нормализуем адрес коллекции
            const parsedCollectionAddress = Address.parse(collectionAddress);
            normalizedCollectionAddress = parsedCollectionAddress.toString();

            console.log('🔧 Нормализованные адреса:', {
                originalNft: nftAddress,
                normalizedNft: normalizedNftAddress,
                originalCollection: collectionAddress,
                normalizedCollection: normalizedCollectionAddress
            });
        } catch (addressError) {
            console.error('❌ Ошибка парсинга адресов:', addressError);
            return res.status(400).json({ 
                error: 'Некорректный формат адреса NFT или коллекции' 
            });
        }

        // Проверяем, что коллекция в whitelist
        if (!whitelist.includes(normalizedCollectionAddress)) {
            console.warn('⚠️ Коллекция не в whitelist:', {
                collectionAddress: normalizedCollectionAddress,
                whitelistSize: whitelist.length
            });
            return res.status(404).json({ error: 'Коллекция не найдена в whitelist' });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // СНАЧАЛА убеждаемся, что NFT существует в таблице nfts
            let nftMetadata = {};
            
            // Проверяем, есть ли NFT в базе данных
            const existingNft = await client.query('SELECT address, metadata FROM nfts WHERE address = $1', [normalizedNftAddress]);
            
            if (existingNft.rows.length === 0) {
                // NFT еще нет в базе, получаем его метаданные и создаем запись
                console.log('🔍 NFT не найден в базе, получаем метаданные:', normalizedNftAddress);
                
                try {
                    const nftInfo = await tonapi.nft.getNftItemByAddress(normalizedNftAddress);
                    nftMetadata = nftInfo.metadata || {};
                    console.log('✅ Метаданные получены для NFT:', nftInfo.metadata?.name || normalizedNftAddress);
                } catch (apiError) {
                    console.log('⚠️ Не удалось получить метаданные для NFT', normalizedNftAddress, 'используем базовые');
                    nftMetadata = {
                        name: `NFT ${normalizedNftAddress.slice(-6)}`,
                        description: 'NFT из коллекции'
                    };
                }

                // СОЗДАЕМ запись NFT В ПЕРВУЮ ОЧЕРЕДЬ
                await client.query(`
                    INSERT INTO nfts (address, collection_address, metadata, first_listen, updated_at)
                    VALUES ($1, $2, $3, NOW(), NOW())
                `, [normalizedNftAddress, normalizedCollectionAddress, JSON.stringify(nftMetadata)]);

                console.log('✅ Создана новая запись NFT в базе данных');
            } else {
                // NFT уже существует, используем существующие метаданные
                nftMetadata = existingNft.rows[0].metadata || {};
                console.log('📋 NFT уже существует в базе данных');
                
                // Обновляем collection_address на случай, если он изменился
                await client.query(`
                    UPDATE nfts 
                    SET collection_address = $1, updated_at = NOW()
                    WHERE address = $2
                `, [normalizedCollectionAddress, normalizedNftAddress]);
            }

            // ТЕПЕРЬ создаем/обновляем запись прослушивания
            const listenResult = await client.query(`
                INSERT INTO listens (nft_address, collection_address, count, last_updated)
                VALUES ($1, $2, 1, NOW())
                ON CONFLICT (nft_address)
                DO UPDATE SET 
                    count = listens.count + 1,
                    last_updated = NOW()
                RETURNING count
            `, [normalizedNftAddress, normalizedCollectionAddress]);

            const newCount = listenResult.rows[0]?.count || 1;

            await client.query('COMMIT');            
            
            res.json({ 
                success: true, 
                count: newCount,
                message: 'Прослушивание записано успешно'
            });
            
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('❌ Ошибка транзакции записи прослушивания:', error);
            throw error;
        } finally {
            client.release();
        }
        
    } catch (error) {
        console.error('❌ Критическая ошибка при записи прослушивания:', error);
        res.status(500).json({ 
            error: 'Ошибка сервера при записи прослушивания',
            details: error instanceof Error ? error.message : 'Неизвестная ошибка'
        });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const statsQuery = `
            SELECT 
                COUNT(DISTINCT l.nft_address) as total_nfts_listened,
                SUM(l.count) as total_listens,
                COUNT(DISTINCT l.collection_address) as total_collections
            FROM listens l
            WHERE l.collection_address = ANY($1)
        `;
        
        const result = await pool.query(statsQuery, [whitelist]);
        const stats = result.rows[0];

        res.json({
            totalNftsListened: parseInt(stats.total_nfts_listened) || 0,
            totalListens: parseInt(stats.total_listens) || 0,
            totalCollections: parseInt(stats.total_collections) || 0
        });
        
    } catch (error) {
        console.error('Ошибка при получении статистики:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/sync-status', async (req, res) => {
    try {
        const collectionsQuery = `
            SELECT 
                COUNT(*) as total_collections,
                COUNT(CASE WHEN updated_at > NOW() - INTERVAL '24 hours' THEN 1 END) as recently_updated_collections
            FROM collections
        `;
        
        const nftsQuery = `
            SELECT 
                COUNT(*) as total_nfts,
                COUNT(CASE WHEN updated_at > NOW() - INTERVAL '24 hours' THEN 1 END) as recently_updated_nfts
            FROM nfts
        `;
        
        const listensQuery = `
            SELECT 
                COUNT(*) as total_listens_records,
                SUM(count) as total_listens
            FROM listens
        `;
        
        const [collectionsResult, nftsResult, listensResult] = await Promise.all([
            pool.query(collectionsQuery),
            pool.query(nftsQuery),
            pool.query(listensQuery)
        ]);

        res.json({
            collections: {
                total: parseInt(collectionsResult.rows[0].total_collections) || 0,
                recentlyUpdated: parseInt(collectionsResult.rows[0].recently_updated_collections) || 0
            },
            nfts: {
                total: parseInt(nftsResult.rows[0].total_nfts) || 0,
                recentlyUpdated: parseInt(nftsResult.rows[0].recently_updated_nfts) || 0
            },
            listens: {
                totalRecords: parseInt(listensResult.rows[0].total_listens_records) || 0,
                totalListens: parseInt(listensResult.rows[0].total_listens) || 0
            },
            whitelistSize: whitelist.length,
            lastSyncTime: lastSyncTime?.toISOString() || null,
            syncInProgress: syncInProgress
        });
        
    } catch (error) {
        console.error('Ошибка при получении статуса синхронизации:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Admin endpoints
app.post('/admin/sync', async (req, res) => {
    try {
        const { adminKey } = req.body;
        
        if (adminKey !== process.env.ADMIN_KEY) {
            return res.status(403).json({ error: 'Неверный админ ключ' });
        }
        
        console.log('🔧 Запуск ручной синхронизации...');
        
        // Start sync in background
        performFullSync().catch(error => {
            console.error('❌ Ошибка фоновой синхронизации:', error);
        });
        
        res.json({ success: true, message: 'Синхронизация запущена' });
        
    } catch (error) {
        console.error('Ошибка ручной синхронизации:', error);
        res.status(500).json({ error: 'Ошибка синхронизации' });
    }
});

// Health check
app.get('/health', async (req, res) => {
    try {
        // Check database connection
        await pool.query('SELECT 1');
        
        res.json({
            status: 'healthy',
            database: 'connected',
            lastSync: lastSyncTime?.toISOString() || null,
            syncInProgress: syncInProgress,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
});

app.get('/', (req, res) => {
    res.json({
        name: 'NFT Music Backend',
        version: '1.0.0',
        status: 'running',
        endpoints: {
            public: [
                'GET /api/collections',
                'GET /api/collections/:address/top-nfts',
                'POST /api/listens',
                'GET /api/stats',
                'GET /api/sync-status',
                'GET /health'
            ],
            protected: [
                'POST /ton-proof/generatePayload',
                'POST /ton-proof/checkProof',
                'POST /dapp/generateMusicApiKey',
                'GET /dapp/getAccountInfo',
                'GET /dapp/getNFTs'
            ],
            admin: [
                'POST /admin/sync'
            ]
        }
    });
});

// App initialization
async function initializeApp() {
  try {
    console.log('🚀 Инициализация приложения...');
    
    // Initialize database
    await initializeDatabase();
    
    // Perform initial sync
    await performFullSync();
    
    // Setup periodic sync every 6 hours
    setInterval(async () => {
      console.log('⏰ Запуск периодической синхронизации...');
      await performFullSync();
    }, 6 * 60 * 60 * 1000); // 6 hours
    
    console.log('✅ Приложение инициализировано успешно');
    
  } catch (error) {
    console.error('❌ Ошибка инициализации приложения:', error);
    throw error;
  }
}

// Start server
initializeApp().then(() => {
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`🌟 Сервер запущен на порту ${port}`);
        console.log(`🔄 Автоматическая синхронизация активна (каждые 6 часов)`);
        console.log(`📊 Whitelist содержит ${whitelist.length} коллекций`);
        console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
}).catch(error => {
    console.error('💥 Критическая ошибка запуска приложения:', error);
    process.exit(1);
});