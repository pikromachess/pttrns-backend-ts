import { Express } from 'express';
import * as jsonwebtoken from 'jsonwebtoken';
import { generatePayload, db } from '../services/payloadService';
import { checkProof } from '../services/proofService';
import { keysLimiter, strictLimiter } from '../middleware/middleware';
import { TonProof } from '../types/tonProof';

const backendSecret = process.env.BACKEND_SECRET || 'MY_SECRET_FROM_ENV';
const recreatePayloadFrequency = 1000 * 60 * 10;

export function tonProofRoutes(app: Express) {
  // Generate payload for TON Connect
  app.post('/ton-proof/generatePayload', keysLimiter, (req, res) => {
    const payload = generatePayload();
    db.payloads.push(payload);

    setTimeout(() => {
      db.payloads = db.payloads.filter(p => p !== payload);
    }, recreatePayloadFrequency);

    res.json({ payload });
  });

  // Check TON proof and return JWT token
  app.post('/ton-proof/checkProof', strictLimiter, async (req, res) => {
    try {
      const tonProof = req.body as TonProof;
      const isValid = await checkProof(tonProof);

      if (isValid) {
        const token = jsonwebtoken.sign(tonProof.address, backendSecret);
        res.json({ token });
      } else {
        res.status(400).json({ error: 'Wrong proof' });
      }
    } catch (error) {
      console.error('Ошибка проверки TON proof:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });
}