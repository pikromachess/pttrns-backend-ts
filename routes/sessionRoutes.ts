import { Express } from 'express';
import { Address, Cell, loadStateInit } from '@ton/core';
import * as jwt from 'jsonwebtoken';
import { SignDataService } from '../services/signDataService';
import { 
  checkSession, 
  detectSuspiciousActivity,
  addSession,
  getUserSession,
  getSession
} from '../middleware/middleware';
import { pool } from '../database/database';
import { tonapi } from '../services/tonapi';
import * as fs from 'fs';
import * as path from 'path';

const backendSecret = process.env.BACKEND_SECRET || 'MY_SECRET_FROM_ENV';
const musicBackendUrl = process.env.MUSIC_BACKEND_URL || 'http://localhost:8000';

// Load whitelist
const whitelistPath = path.join(__dirname, '../whitelist.json');
const whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')).collections;

const signDataService = new SignDataService();

// Функция для извлечения публичного ключа из StateInit
function tryParsePublicKey(stateInit: any): Buffer | null {
  try {
    // Попытка извлечь публичный ключ из data ячейки StateInit
    if (stateInit.data && stateInit.data.bits) {
      const dataSlice = stateInit.data.beginParse();
      
      // Для кошельков v3/v4 публичный ключ обычно находится после seqno (32 бита)
      try {
        dataSlice.loadUint(32); // пропускаем seqno
        const publicKey = dataSlice.loadBuffer(32); // загружаем 32 байта публичного ключа
        return publicKey;
      } catch (parseError) {
        console.warn('⚠️ Не удалось распарсить публичный ключ из data:', parseError);
      }
    }
    
    return null;
  } catch (error) {
    console.error('❌ Ошибка парсинга публичного ключа из StateInit:', error);
    return null;
  }
}

// Функция для получения публичного ключа кошелька
async function getWalletPublicKey(address: string): Promise<Buffer | null> {
  try {
    console.log('🔑 Получаем публичный ключ для адреса через get-метод:', address);
    
    // Пытаемся получить публичный ключ через get_public_key метод
    try {
      const getMethodResult = await tonapi.blockchain.execGetMethodForBlockchainAccount(
        address,
        'get_public_key'
      );
      
      console.log('📋 Результат get_public_key:', getMethodResult);
      
      if (getMethodResult.stack && getMethodResult.stack.length > 0) {
        const publicKeyItem = getMethodResult.stack[0];
        console.log('🔍 Элемент публичного ключа:', publicKeyItem);
        
        // Используем any для обхода проблем с типами
        const item = publicKeyItem as any;
        
        // Проверяем различные возможные форматы
        if (item.type === 'num' && item.num) {
          const publicKeyBigInt = BigInt(item.num);
          const publicKeyHex = publicKeyBigInt.toString(16).padStart(64, '0');
          const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
          console.log('✅ Публичный ключ получен через get_public_key (num), длина:', publicKeyBuffer.length);
          return publicKeyBuffer;
        } else if (item.type === 'cell' && item.cell) {
          try {
            const cell = Cell.fromBase64(item.cell.bytes || item.cell);
            const slice = cell.beginParse();
            const publicKeyBuffer = slice.loadBuffer(32);
            console.log('✅ Публичный ключ получен через get_public_key (cell), длина:', publicKeyBuffer.length);
            return publicKeyBuffer;
          } catch (cellParseError) {
            console.warn('⚠️ Ошибка парсинга cell с публичным ключом:', cellParseError);
          }
        } else if (item.value || item.number) {
          // Альтернативные поля для числового значения
          const value = item.value || item.number;
          const publicKeyBigInt = BigInt(value);
          const publicKeyHex = publicKeyBigInt.toString(16).padStart(64, '0');
          const publicKeyBuffer = Buffer.from(publicKeyHex, 'hex');
          console.log('✅ Публичный ключ получен через get_public_key (value), длина:', publicKeyBuffer.length);
          return publicKeyBuffer;
        }
        
        console.warn('⚠️ Неизвестный формат элемента стека:', item);
      }
    } catch (getMethodError) {
      console.warn('⚠️ Не удалось получить публичный ключ через get_public_key:', getMethodError);
    }

    console.warn('❌ Не удалось получить публичный ключ для адреса:', address);
    return null;

  } catch (error) {
    console.error('❌ Ошибка получения публичного ключа:', error);
    return null;
  }
}

// Интерфейсы
interface SignDataRequest {
  signature: string;
  address: string;
  timestamp: number;
  domain: string;
  payload: {
    type: 'text';  // Исправляем: используем литеральный тип
    text: string;
  };
  public_key: string;
  walletStateInit: string;
}

interface NftListenRequest {
  nftAddress: string;
  timestamp: number;
}

interface SessionData {
  sessionId: string;
  userAddress: string;
  createdAt: Date;
  expiresAt: Date;
  signatureVerified: boolean;
}

export function sessionRoutes(app: Express) {
  // Create listening session
  app.post('/api/session/create', async (req, res) => {
    try {
      const signData: SignDataRequest = req.body;

      console.log('🔐 Получен запрос на создание сессии:', {
        address: signData.address,
        domain: signData.domain,
        timestamp: signData.timestamp
      });

      // Проверяем базовые параметры
      if (!signData.signature || !signData.address || !signData.timestamp || !signData.domain || !signData.payload) {
        return res.status(400).json({ error: 'Неполные данные подписи' });
      }

      // Проверяем тип payload
      if (signData.payload.type !== 'text' || !signData.payload.text) {
        return res.status(400).json({ error: 'Неверный тип данных подписи' });
      }

      // Проверяем временную метку (не старше 5 минут)
      const nowTimestamp = Math.floor(Date.now() / 1000);
      if (nowTimestamp - signData.timestamp > 5 * 60) {
        return res.status(400).json({ error: 'Подпись устарела' });
      }

      // Проверяем содержимое сообщения
      const expectedText = "Подтвердите начало сессии прослушивания. Подписывая это сообщение, вы соглашаетесь с условиями честного использования NFT-аудио в рамках децентрализованной платформы. \nВаша подпись верифицируется в блокчейне и подтверждает легальное прослушивание токенизированного контента. \nСессия длится 1 час.\n\nPatternsNft";
      
      if (signData.payload.text !== expectedText) {
        return res.status(400).json({ error: 'Неверное содержимое сообщения' });
      }

      // Нормализуем адрес
      let normalizedAddress: string;
      try {
        normalizedAddress = Address.parse(signData.address).toString();
      } catch (error) {
        return res.status(400).json({ error: 'Неверный формат адреса' });
      }

      // Проверяем, есть ли уже активная сессия для этого пользователя
      const existingSessionId = getUserSession(normalizedAddress);
      if (existingSessionId) {
        const existingSession = getSession(existingSessionId);
        if (existingSession && new Date() < existingSession.expiresAt) {
          console.log('✅ Возвращаем существующую сессию');
          return res.json({
            sessionId: existingSessionId,
            musicServerUrl: musicBackendUrl,
            expiresAt: existingSession.expiresAt.toISOString()
          });
        }
      }

      // Верифицируем подпись
      console.log('🔍 Проверяем подпись сообщения...');
      
      // Исправляем: приводим payload к правильному типу
      const signDataPayload = {
        type: 'text' as const,
        text: signData.payload.text
      };
      
      const isValidSignature = await signDataService.checkSignData({
        signature: signData.signature,
        address: normalizedAddress,
        timestamp: signData.timestamp,
        domain: signData.domain,
        payload: signDataPayload,
        public_key: signData.public_key,
        walletStateInit: signData.walletStateInit
      }, getWalletPublicKey); // Теперь функция определена

      if (!isValidSignature) {
        console.warn('❌ Неверная подпись сообщения');
        return res.status(400).json({ error: 'Неверная подпись сообщения' });
      }

      console.log('✅ Подпись верифицирована успешно');

      // Создаем новую сессию
      const sessionId = jwt.sign({
        address: normalizedAddress,
        domain: signData.domain,
        timestamp: signData.timestamp,
        type: 'listening_session'
      }, backendSecret);

      const currentTime = new Date();
      const expiresAt = new Date(currentTime.getTime() + 60 * 60 * 1000); // 1 час

      const sessionData: SessionData = {
        sessionId,
        userAddress: normalizedAddress,
        createdAt: currentTime,
        expiresAt,
        signatureVerified: true
      };

      // Сохраняем сессию в памяти
      addSession(sessionId, sessionData);

      // Сохраняем сессию в базе данных для мониторинга
      try {
        await pool.query(`
          INSERT INTO listening_sessions (session_id, user_address, signature_data, created_at, expires_at)
          VALUES ($1, $2, $3, $4, $5)
        `, [
          sessionId, 
          normalizedAddress, 
          JSON.stringify(signData), 
          currentTime, 
          expiresAt
        ]);
      } catch (dbError) {
        console.error('⚠️ Ошибка сохранения сессии в БД:', dbError);
        // Продолжаем работу, так как основная логика не зависит от БД
      }

      console.log('✅ Сессия создана:', {
        sessionId: sessionId.slice(0, 20) + '...',
        userAddress: normalizedAddress,
        expiresAt: expiresAt.toISOString()
      });

      res.json({
        sessionId,
        musicServerUrl: musicBackendUrl,
        expiresAt: expiresAt.toISOString()
      });

    } catch (error) {
      console.error('❌ Ошибка создания сессии:', error);
      res.status(500).json({ 
        error: 'Ошибка сервера при создании сессии',
        details: error instanceof Error ? error.message : 'Неизвестная ошибка'
      });
    }
  });

  // Validate session
  app.post('/api/session/validate', checkSession, (req, res) => {
    const session = (req as any).session;
    res.json({
      valid: true,
      address: session.userAddress,
      expiresAt: session.expiresAt.toISOString()
    });
  });

  // Record listen with session
  app.post('/api/session-listens', checkSession, async (req, res) => {
    try {
      const session = (req as any).session as SessionData;
      const { nftAddress, timestamp }: NftListenRequest = req.body;

      console.log('📊 Получен запрос на запись прослушивания через сессию:', {
        nftAddress,
        timestamp,
        userAddress: session.userAddress,
        sessionAge: Date.now() - session.createdAt.getTime()
      });

      if (!nftAddress || !timestamp) {
        return res.status(400).json({ error: 'Необходимы nftAddress и timestamp' });
      }

      // Проверяем временную метку (не старше 10 минут и не из будущего)
      const currentTimestamp = Date.now();
      const timeDiff = Math.abs(currentTimestamp - timestamp);
      if (timeDiff > 10 * 60 * 1000) {
        return res.status(400).json({ error: 'Неверная временная метка' });
      }

      // Нормализуем адрес NFT
      let normalizedNftAddress: string;
      try {
        normalizedNftAddress = Address.parse(nftAddress).toString();
      } catch (error) {
        return res.status(400).json({ error: 'Неверный формат адреса NFT' });
      }

      // Получаем информацию о NFT для определения коллекции
      let collectionAddress: string;
      try {
        const nftInfo = await tonapi.nft.getNftItemByAddress(normalizedNftAddress);
        if (!nftInfo.collection?.address) {
          return res.status(400).json({ error: 'NFT не принадлежит к коллекции' });
        }
        
        collectionAddress = Address.parse(nftInfo.collection.address).toString();
        
        // Проверяем, что коллекция в whitelist
        if (!whitelist.includes(collectionAddress)) {
          return res.status(403).json({ error: 'Коллекция не разрешена для прослушивания' });
        }
      } catch (error) {
        console.error('❌ Ошибка получения информации о NFT:', error);
        return res.status(400).json({ error: 'Не удалось получить информацию о NFT' });
      }

      // Детектирование подозрительной активности
      const suspiciousActivity = await detectSuspiciousActivity(session.userAddress, normalizedNftAddress, timestamp);
      if (suspiciousActivity.isSuspicious) {
        console.warn('⚠️ Обнаружена подозрительная активность:', suspiciousActivity.reason);
        return res.status(429).json({ 
          error: 'Обнаружена подозрительная активность',
          reason: suspiciousActivity.reason
        });
      }

      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // Проверяем последнее прослушивание этого NFT пользователем
        const lastListenQuery = `
          SELECT last_recorded, count
          FROM session_listens
          WHERE user_address = $1 AND nft_address = $2
          ORDER BY last_recorded DESC
          LIMIT 1
        `;
        
        const lastListenResult = await client.query(lastListenQuery, [session.userAddress, normalizedNftAddress]);
        
        if (lastListenResult.rows.length > 0) {
          const lastListen = lastListenResult.rows[0];
          const timeSinceLastListen = timestamp - new Date(lastListen.last_recorded).getTime();
          
          // Не позволяем записывать прослушивания чаще чем раз в 30 секунд
          if (timeSinceLastListen < 30000) {
            await client.query('ROLLBACK');
            return res.status(429).json({ error: 'Слишком частые запросы прослушивания' });
          }
        }

        // Создаем/обновляем запись прослушивания пользователя
        const sessionListenResult = await client.query(`
          INSERT INTO session_listens (user_address, nft_address, collection_address, session_id, count, last_recorded)
          VALUES ($1, $2, $3, $4, 1, to_timestamp($5 / 1000.0))
          ON CONFLICT (user_address, nft_address)
          DO UPDATE SET 
            count = session_listens.count + 1,
            last_recorded = to_timestamp($5 / 1000.0),
            session_id = $4
          RETURNING count
        `, [session.userAddress, normalizedNftAddress, collectionAddress, session.sessionId, timestamp]);

        // Обновляем общую статистику прослушиваний
        await client.query(`
          INSERT INTO nfts (address, collection_address, metadata, first_listen, updated_at)
          VALUES ($1, $2, '{}', NOW(), NOW())
          ON CONFLICT (address) 
          DO UPDATE SET 
            collection_address = $2,
            updated_at = NOW()
        `, [normalizedNftAddress, collectionAddress]);

        await client.query(`
          INSERT INTO listens (nft_address, collection_address, count, last_updated)
          VALUES ($1, $2, 1, NOW())
          ON CONFLICT (nft_address)
          DO UPDATE SET 
            count = listens.count + 1,
            last_updated = NOW()
        `, [normalizedNftAddress, collectionAddress]);

        await client.query('COMMIT');

        const userListenCount = sessionListenResult.rows[0]?.count || 1;

        console.log('✅ Прослушивание записано через сессию:', {
          userAddress: session.userAddress,
          nftAddress: normalizedNftAddress,
          userListenCount
        });

        res.json({
          success: true,
          userListenCount,
          message: 'Прослушивание записано успешно'
        });

      } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Ошибка записи прослушивания через сессию:', error);
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      console.error('❌ Критическая ошибка записи прослушивания через сессию:', error);
      res.status(500).json({
        error: 'Ошибка сервера при записи прослушивания',
        details: error instanceof Error ? error.message : 'Неизвестная ошибка'
      });
    }
  });

  // Get user statistics
  app.get('/api/session/user-stats', checkSession, async (req, res) => {
    try {
      const session = (req as any).session as SessionData;
      
      const userStatsQuery = `
        SELECT 
          COUNT(DISTINCT nft_address) as unique_nfts_listened,
          COUNT(DISTINCT collection_address) as unique_collections,
          SUM(count) as total_listens,
          MAX(last_recorded) as last_activity
        FROM session_listens
        WHERE user_address = $1
      `;
      
      const result = await pool.query(userStatsQuery, [session.userAddress]);
      const stats = result.rows[0];
      
      res.json({
        userAddress: session.userAddress,
        uniqueNftsListened: parseInt(stats.unique_nfts_listened) || 0,
        uniqueCollections: parseInt(stats.unique_collections) || 0,
        totalListens: parseInt(stats.total_listens) || 0,
        lastActivity: stats.last_activity,
        sessionExpiresAt: session.expiresAt.toISOString()
      });
      
    } catch (error) {
      console.error('❌ Ошибка получения статистики пользователя:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });
}
