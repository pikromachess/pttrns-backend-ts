import { Express } from 'express';
import { Address } from '@ton/core';
import { pool } from '../database/database';
import { tonapi } from '../services/tonapi';
import * as fs from 'fs';
import * as path from 'path';

// Load whitelist
const whitelistPath = path.join(__dirname, '../whitelist.json');
const whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')).collections;

export function publicApiRoutes(app: Express) {
  // Get all collections with statistics
  app.get('/api/collections', async (req, res) => {
    try {
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

  // Get top NFTs in collection
  app.get('/api/collections/:address/top-nfts', async (req, res) => {
    try {
      const { address } = req.params;
      const limit = parseInt(req.query.limit as string) || 7;

      // Проверяем, что коллекция в whitelist
      if (!whitelist.includes(address)) {
        return res.status(404).json({ error: 'Коллекция не найдена' });
      }

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

  // Get NFTs statistics for collection
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
              if (!apiNft.address) {
                console.warn('⚠️ NFT без адреса:', apiNft);
                return;
              }

              let nftAddress = Address.parse(apiNft.address).toString();
              
              if (!nftMap.has(nftAddress)) {
                nftMap.set(nftAddress, {
                  address: nftAddress,
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

  // Record listen (legacy endpoint)
  app.post('/api/listens', async (req, res) => {
    try {
      const { nftAddress, collectionAddress } = req.body;

      console.log('📊 Получен запрос на запись прослушивания (legacy):', {
        nftAddress,
        collectionAddress,
        timestamp: new Date().toISOString()
      });

      if (!nftAddress || !collectionAddress) {
        console.warn('❌ Отсутствуют обязательные параметры');
        return res.status(400).json({ 
          error: 'Необходимы nftAddress и collectionAddress' 
        });
      }

      // Нормализуем адреса
      let normalizedNftAddress: string;
      let normalizedCollectionAddress: string;

      try {
        normalizedNftAddress = Address.parse(nftAddress).toString();
        normalizedCollectionAddress = Address.parse(collectionAddress).toString();
      } catch (addressError) {
        console.error('❌ Ошибка парсинга адресов:', addressError);
        return res.status(400).json({ 
          error: 'Некорректный формат адреса NFT или коллекции' 
        });
      }

      // Проверяем, что коллекция в whitelist
      if (!whitelist.includes(normalizedCollectionAddress)) {
        console.warn('⚠️ Коллекция не в whitelist:', normalizedCollectionAddress);
        return res.status(404).json({ error: 'Коллекция не найдена в whitelist' });
      }

      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // Убеждаемся, что NFT существует в таблице nfts
        let nftMetadata = {};
        
        const existingNft = await client.query('SELECT address, metadata FROM nfts WHERE address = $1', [normalizedNftAddress]);
        
        if (existingNft.rows.length === 0) {
          console.log('🔍 NFT не найден в базе, получаем метаданные:', normalizedNftAddress);
          
          try {
            const nftInfo = await tonapi.nft.getNftItemByAddress(normalizedNftAddress);
            nftMetadata = nftInfo.metadata || {};
            console.log('✅ Метаданные получены для NFT:', nftInfo.metadata?.name || normalizedNftAddress);
          } catch (apiError) {
            console.log('⚠️ Не удалось получить метаданные для NFT', normalizedNftAddress);
            nftMetadata = {
              name: `NFT ${normalizedNftAddress.slice(-6)}`,
              description: 'NFT из коллекции'
            };
          }

          await client.query(`
            INSERT INTO nfts (address, collection_address, metadata, first_listen, updated_at)
            VALUES ($1, $2, $3, NOW(), NOW())
          `, [normalizedNftAddress, normalizedCollectionAddress, JSON.stringify(nftMetadata)]);

          console.log('✅ Создана новая запись NFT в базе данных');
        } else {
          console.log('📋 NFT уже существует в базе данных');
          
          await client.query(`
            UPDATE nfts 
            SET collection_address = $1, updated_at = NOW()
            WHERE address = $2
          `, [normalizedCollectionAddress, normalizedNftAddress]);
        }

        // Создаем/обновляем запись прослушивания
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

  // Get general statistics
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

  // Get sync status
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

      const { getLastSyncTime, getSyncInProgress } = await import('../services/syncService');

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
        lastSyncTime: getLastSyncTime()?.toISOString() || null,
        syncInProgress: getSyncInProgress()
      });
      
    } catch (error) {
      console.error('Ошибка при получении статуса синхронизации:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });
}