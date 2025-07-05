import { Express, Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import * as jsonwebtoken from 'jsonwebtoken';
import { pool } from '../database/database';
import { Address } from '@ton/core';

const backendSecret = process.env.BACKEND_SECRET || 'MY_SECRET_FROM_ENV';

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

// JWT middleware
export async function checkJWT(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.split('Bearer ')[1];

  if (!token) {
    res.sendStatus(401);
    return;
  }

  jsonwebtoken.verify(token, backendSecret, (err, decoded) => {
    if (err) {
      res.sendStatus(401);
      return;
    }

    (req as any).userAddress = decoded as string;
    next();
  });
}

// Session data interface
interface SessionData {
  sessionId: string;
  userAddress: string;
  createdAt: Date;
  expiresAt: Date;
  signatureVerified: boolean;
}

// In-memory session storage
const activeSessions = new Map<string, SessionData>();
const userSessions = new Map<string, string>(); // address -> sessionId

// Session cleanup interval
setInterval(() => {
  const now = new Date();
  for (const [sessionId, session] of activeSessions.entries()) {
    if (now > session.expiresAt) {
      activeSessions.delete(sessionId);
      userSessions.delete(session.userAddress);
      console.log(`🧹 Удалена истекшая сессия: ${sessionId}`);
    }
  }
}, 5 * 60 * 1000); // Каждые 5 минут

// Session middleware
export async function checkSession(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Отсутствует токен сессии' });
  }

  const sessionId = authHeader.split(' ')[1];
  const session = activeSessions.get(sessionId);

  if (!session) {
    return res.status(401).json({ error: 'Недействительная сессия' });
  }

  if (new Date() > session.expiresAt) {
    activeSessions.delete(sessionId);
    userSessions.delete(session.userAddress);
    return res.status(401).json({ error: 'Сессия истекла' });
  }

  (req as any).session = session;
  next();
}

// User block check
export async function checkUserBlock(userAddress: string): Promise<{isBlocked: boolean, reason?: string}> {
  try {
    const blockQuery = `
      SELECT reason, blocked_until 
      FROM user_blocks 
      WHERE user_address = $1 
      AND is_active = TRUE 
      AND (blocked_until IS NULL OR blocked_until > NOW())
    `;

    const result = await pool.query(blockQuery, [userAddress]);
    
    if (result.rows.length > 0) {
      return {
        isBlocked: true,
        reason: result.rows[0].reason
      };
    }

    return { isBlocked: false };
  } catch (error) {
    console.error('Ошибка проверки блокировки:', error);
    return { isBlocked: false }; // В случае ошибки не блокируем
  }
}

// Suspicious activity logger
export async function logSuspiciousActivity(
  userAddress: string, 
  activityType: string, 
  description: string, 
  severity: 'low' | 'medium' | 'high' | 'critical' = 'medium',
  metadata: any = {}
) {
  try {
    await pool.query(`
      INSERT INTO suspicious_activities (user_address, activity_type, description, severity, metadata)
      VALUES ($1, $2, $3, $4, $5)
    `, [userAddress, activityType, description, severity, JSON.stringify(metadata)]);

    console.log(`⚠️ Записана подозрительная активность: ${activityType} для ${userAddress}`);
  } catch (error) {
    console.error('Ошибка записи подозрительной активности:', error);
  }
}

// Suspicious activity detection
export async function detectSuspiciousActivity(
  userAddress: string, 
  nftAddress: string, 
  timestamp: number
): Promise<{isSuspicious: boolean, reason?: string}> {
  try {
    // Проверяем блокировку пользователя
    const blockCheck = await checkUserBlock(userAddress);
    if (blockCheck.isBlocked) {
      return { 
        isSuspicious: true, 
        reason: `Пользователь заблокирован: ${blockCheck.reason}`
      };
    }

    const client = await pool.connect();
    
    try {
      const now = Date.now();
      const oneHourAgo = now - 60 * 60 * 1000;
      const oneDayAgo = now - 24 * 60 * 60 * 1000;

      // 1. Проверяем количество прослушиваний за последний час
      const hourlyListensQuery = `
        SELECT COUNT(*) as count
        FROM session_listens
        WHERE user_address = $1 
        AND last_recorded > to_timestamp($2 / 1000.0)
      `;
      
      const hourlyResult = await client.query(hourlyListensQuery, [userAddress, oneHourAgo]);
      const hourlyListens = parseInt(hourlyResult.rows[0]?.count || '0');
      
      if (hourlyListens > 50) {
        await logSuspiciousActivity(
          userAddress, 
          'excessive_hourly_listens', 
          `${hourlyListens} прослушиваний за час`,
          'high',
          { hourlyListens, limit: 50 }
        );
        return { isSuspicious: true, reason: 'Превышено количество прослушиваний в час' };
      }

      // 2. Проверяем количество прослушиваний за день
      const dailyListensQuery = `
        SELECT COUNT(*) as count
        FROM session_listens
        WHERE user_address = $1 
        AND last_recorded > to_timestamp($2 / 1000.0)
      `;
      
      const dailyResult = await client.query(dailyListensQuery, [userAddress, oneDayAgo]);
      const dailyListens = parseInt(dailyResult.rows[0]?.count || '0');
      
      if (dailyListens > 500) {
        await logSuspiciousActivity(
          userAddress, 
          'excessive_daily_listens', 
          `${dailyListens} прослушиваний за день`,
          'critical',
          { dailyListens, limit: 500 }
        );
        return { isSuspicious: true, reason: 'Превышено количество прослушиваний в день' };
      }

      // 3. Проверяем паттерны одинаковых NFT
      const recentSameNftQuery = `
        SELECT COUNT(*) as count
        FROM session_listens
        WHERE user_address = $1 
        AND nft_address = $2
        AND last_recorded > to_timestamp($3 / 1000.0)
      `;
      
      const recentSameNftResult = await client.query(recentSameNftQuery, [userAddress, nftAddress, oneHourAgo]);
      const recentSameNftListens = parseInt(recentSameNftResult.rows[0]?.count || '0');
      
      if (recentSameNftListens > 10) {
        await logSuspiciousActivity(
          userAddress, 
          'excessive_same_nft_listens', 
          `${recentSameNftListens} прослушиваний одного NFT за час`,
          'medium',
          { nftAddress, recentListens: recentSameNftListens, limit: 10 }
        );
        return { isSuspicious: true, reason: 'Слишком много прослушиваний одного NFT' };
      }

      return { isSuspicious: false };
      
    } finally {
      client.release();
    }
    
  } catch (error) {
    console.error('❌ Ошибка детектирования подозрительной активности:', error);
    return { isSuspicious: false };
  }
}

// Session management functions
export function addSession(sessionId: string, sessionData: SessionData) {
  activeSessions.set(sessionId, sessionData);
  userSessions.set(sessionData.userAddress, sessionId);
}

export function getSession(sessionId: string): SessionData | undefined {
  return activeSessions.get(sessionId);
}

export function getUserSession(userAddress: string): string | undefined {
  return userSessions.get(userAddress);
}

export function removeSession(sessionId: string) {
  const session = activeSessions.get(sessionId);
  if (session) {
    activeSessions.delete(sessionId);
    userSessions.delete(session.userAddress);
  }
}

// Setup middleware
export function setupMiddleware(app: Express) {
  app.use(apiLimiter);
}

// Export rate limiters for specific routes
export { strictLimiter, keysLimiter };