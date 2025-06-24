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
import { Address } from "@ton/core";
import { Pool } from 'pg';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const backendSecret = process.env.BACKEND_SECRET || 'MY_SECRET_FROM_ENV';
const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173'; 
const musicBackendUrl = process.env.MUSIC_BACKEND_URL || 'http://localhost:8000';

const recreatePayloadFrequency = 1000 * 60 * 10;

const whitelistPath = path.join(__dirname, 'whitelist.json');
const whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')).collections;

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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function saveApiKey(apiKey: string, address: string, created: Date, expires: Date) {
  const client = await pool.connect();
  address = Address.parse(address).toString();
  try {
    await client.query('BEGIN');
    
    // Удаляем старые ключи пользователя (включая истёкшие)
    await client.query(
      'DELETE FROM api_keys WHERE address = $1 OR expires_at < NOW()',
      [address]
    );
    
    // Создаём новый ключ
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

app.use(apiLimiter); // Базовый лимитер для всех API

app.post('/ton-proof/generatePayload', strictLimiter, (req, res) => {
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

app.post('/dapp/generateMusicApiKey', strictLimiter, checkJWT, async (req, res) => {
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

app.listen(3000);