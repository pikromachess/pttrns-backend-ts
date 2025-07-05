import { Express } from 'express';
import { Address } from '@ton/core';
import { checkJWT, keysLimiter, strictLimiter } from '../middleware/middleware';
import { saveApiKey, validateApiKey } from '../services/apiKeyService';
import { tonapi } from '../services/tonapi';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const musicBackendUrl = process.env.MUSIC_BACKEND_URL || 'http://localhost:8000';

// Load whitelist
const whitelistPath = path.join(__dirname, '../whitelist.json');
const whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')).collections;

export function dappRoutes(app: Express) {
  // Generate music API key
  app.post('/dapp/generateMusicApiKey', keysLimiter, checkJWT, async (req, res) => {
    try {
      const userAddress = (req as any).userAddress;
      
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
  });

  // Get account info
  app.get('/dapp/getAccountInfo', strictLimiter, checkJWT, async (req, res) => {
    try {
      res.json({ address: (req as any).userAddress });
    } catch (error) {
      console.error('Ошибка получения информации аккаунта:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });

  // Get user's NFTs
  app.get('/dapp/getNFTs', strictLimiter, checkJWT, async (req, res) => {
    try {
      const userAddress = (req as any).userAddress;
      const { network = 'mainnet', limit = 100, offset = 0 } = req.query;

      // Проверяем, что пользователь запрашивает свои NFT
      if (req.query.walletAddress && req.query.walletAddress !== userAddress) {
        return res.status(403).json({ error: 'Нет доступа к NFT этого адреса' });
      }

      console.log('🔍 Загружаем NFT для пользователя:', {
        userAddress,
        network,
        limit: parseInt(limit as string),
        offset: parseInt(offset as string)
      });

      // Получаем NFT пользователя через TON API
      const nftItems = await tonapi.accounts.getAccountNftItems(
        userAddress,
        {
          limit: parseInt(limit as string),
          offset: parseInt(offset as string),
          indirect_ownership: false
        }
      );

      console.log('📡 Получено NFT из TON API:', nftItems.nft_items.length);

      // Фильтруем только NFT из разрешенных коллекций
      const filteredNfts = nftItems.nft_items.filter(nft => {                
        if (!nft.collection) {
          console.log('⚠️ NFT без коллекции:', nft.address);
          return false;
        }
        
        try {
          const normalizedCollectionAddress = Address.parse(nft.collection.address).toString();
          const isWhitelisted = whitelist.includes(normalizedCollectionAddress);
          
          if (!isWhitelisted) {
            console.log('❌ Коллекция не в whitelist:', normalizedCollectionAddress);
          }
          
          return isWhitelisted;
        } catch (error) {
          console.error('❌ Ошибка парсинга адреса коллекции:', nft.collection.address, error);
          return false;
        }
      });

      console.log('✅ NFT после фильтрации по whitelist:', filteredNfts.length);

      // Форматируем NFT для ответа
      const formattedNfts = filteredNfts.map(nft => {
        try {
          return {
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
            trust: nft.metadata?.trust || 'unknown',
            audioUrl: nft.metadata?.audioUrl
          };
        } catch (error) {
          console.error('❌ Ошибка форматирования NFT:', nft.address, error);
          return null;
        }
      }).filter(nft => nft !== null); // Удаляем null значения

      console.log('✅ Успешно отформатировано NFT:', formattedNfts.length);

      res.json({
        data: {
          nft_items: formattedNfts
        },
        total: formattedNfts.length,
        hasMore: nftItems.nft_items.length === parseInt(limit as string)
      });

    } catch (error) {
      console.error('❌ Ошибка при получении NFT:', error);
      
      // Определяем тип ошибки для более точного ответа
      if (error instanceof Error) {
        if (error.message.includes('404')) {
          return res.status(404).json({ 
            error: 'Аккаунт не найден',
            details: 'Убедитесь, что адрес кошелька корректен'
          });
        } else if (error.message.includes('429')) {
          return res.status(429).json({ 
            error: 'Слишком много запросов',
            details: 'Попробуйте позже'
          });
        } else if (error.message.includes('timeout')) {
          return res.status(504).json({ 
            error: 'Превышено время ожидания',
            details: 'TON API не отвечает'
          });
        }
      }
      
      res.status(500).json({ 
        error: 'Ошибка при загрузке NFT',
        details: error instanceof Error ? error.message : 'Неизвестная ошибка'
      });
    }
  });

  // Validate music API key
  app.post('/api/validateMusicApiKey', async (req, res) => {
    try {
      const { apiKey } = req.body;
      
      if (!apiKey) {
        return res.status(400).json({ 
          valid: false, 
          error: 'API ключ не предоставлен' 
        });
      }
      
      console.log('🔑 Проверяем музыкальный API ключ:', apiKey.slice(0, 8) + '...');
      
      const keyData = await validateApiKey(apiKey);
      
      if (!keyData) {
        console.warn('❌ Недействительный или истекший API ключ');
        return res.status(401).json({ 
          valid: false, 
          error: 'Недействительный или истекший API ключ' 
        });
      }
      
      console.log('✅ API ключ валиден для адреса:', keyData.address);
      
      res.json({
        valid: true,
        address: keyData.address,
        expiresAt: keyData.expires.toISOString()
      });
      
    } catch (error) {
      console.error('❌ Ошибка при проверке API ключа:', error);
      res.status(500).json({ 
        valid: false, 
        error: 'Ошибка сервера при проверке API ключа' 
      });
    }
  });

  // Get user's API key info
  app.get('/dapp/getApiKeyInfo', strictLimiter, checkJWT, async (req, res) => {
    try {
      const userAddress = (req as any).userAddress;
      
      console.log('🔍 Получаем информацию об API ключе для:', userAddress);
      
      // Здесь можно добавить логику получения информации о текущем API ключе пользователя
      // Пока возвращаем базовую информацию
      
      res.json({
        userAddress,
        musicServerUrl: musicBackendUrl,
        hasActiveKey: false, // Можно добавить проверку в базе данных
        message: 'Для получения доступа к музыкальному серверу сгенерируйте API ключ'
      });
      
    } catch (error) {
      console.error('❌ Ошибка получения информации об API ключе:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });

  // Health check for DApp endpoints
  app.get('/dapp/health', (req, res) => {
    res.json({
      status: 'healthy',
      service: 'dapp-endpoints',
      timestamp: new Date().toISOString(),
      musicBackendUrl,
      whitelistedCollections: whitelist.length
    });
  });
}