import { Express } from 'express';
import { Address } from '@ton/core';
import { pool } from '../database/database';
import { performFullSync } from '../services/syncService';

export function adminRoutes(app: Express) {
  // Get sessions statistics
  app.get('/admin/sessions-stats', async (req, res) => {
    try {
      const { adminKey } = req.query;
      
      if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Неверный админ ключ' });
      }

      const statsQuery = `
        SELECT 
          COUNT(*) as total_sessions,
          COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_sessions,
          COUNT(CASE WHEN expires_at > NOW() AND is_active = TRUE THEN 1 END) as valid_sessions,
          COUNT(CASE WHEN created_at > NOW() - INTERVAL '24 hours' THEN 1 END) as sessions_24h,
          COUNT(CASE WHEN created_at > NOW() - INTERVAL '1 hour' THEN 1 END) as sessions_1h,
          AVG(EXTRACT(EPOCH FROM (expires_at - created_at))/3600) as avg_session_duration_hours
        FROM listening_sessions
      `;

      const result = await pool.query(statsQuery);
      const stats = result.rows[0];

      // Получаем топ пользователей по активности
      const topUsersQuery = `
        SELECT 
          user_address,
          COUNT(*) as session_count,
          MAX(created_at) as last_session,
          SUM(CASE WHEN is_active = TRUE THEN 1 ELSE 0 END) as active_sessions
        FROM listening_sessions
        WHERE created_at > NOW() - INTERVAL '7 days'
        GROUP BY user_address
        ORDER BY session_count DESC
        LIMIT 10
      `;

      const topUsersResult = await pool.query(topUsersQuery);

      res.json({
        sessions: {
          total: parseInt(stats.total_sessions) || 0,
          active: parseInt(stats.active_sessions) || 0,
          valid: parseInt(stats.valid_sessions) || 0,
          created24h: parseInt(stats.sessions_24h) || 0,
          created1h: parseInt(stats.sessions_1h) || 0,
          avgDurationHours: parseFloat(stats.avg_session_duration_hours) || 0
        },
        topUsers: topUsersResult.rows.map(row => ({
          address: row.user_address,
          sessionCount: parseInt(row.session_count),
          lastSession: row.last_session,
          activeSessions: parseInt(row.active_sessions)
        }))
      });

    } catch (error) {
      console.error('Ошибка получения статистики сессий:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });

  // Get suspicious activities
  app.get('/admin/suspicious-activities', async (req, res) => {
    try {
      const { adminKey, limit = 50, severity } = req.query;
      
      if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Неверный админ ключ' });
      }

      let whereClause = '';
      const queryParams: any[] = [parseInt(limit as string)];

      if (severity) {
        whereClause = 'WHERE severity = $2';
        queryParams.push(severity);
      }

      const activitiesQuery = `
        SELECT 
          id,
          user_address,
          activity_type,
          description,
          metadata,
          severity,
          detected_at,
          resolved_at,
          is_resolved
        FROM suspicious_activities
        ${whereClause}
        ORDER BY detected_at DESC
        LIMIT $1
      `;

      const result = await pool.query(activitiesQuery, queryParams);

      // Получаем статистику по типам активности
      const statsQuery = `
        SELECT 
          activity_type,
          severity,
          COUNT(*) as count,
          COUNT(CASE WHEN detected_at > NOW() - INTERVAL '24 hours' THEN 1 END) as count_24h
        FROM suspicious_activities
        WHERE detected_at > NOW() - INTERVAL '7 days'
        GROUP BY activity_type, severity
        ORDER BY count DESC
      `;

      const statsResult = await pool.query(statsQuery);

      res.json({
        activities: result.rows.map(row => ({
          id: row.id,
          userAddress: row.user_address,
          activityType: row.activity_type,
          description: row.description,
          metadata: row.metadata,
          severity: row.severity,
          detectedAt: row.detected_at,
          resolvedAt: row.resolved_at,
          isResolved: row.is_resolved
        })),
        stats: statsResult.rows.map(row => ({
          activityType: row.activity_type,
          severity: row.severity,
          count: parseInt(row.count),
          count24h: parseInt(row.count_24h)
        }))
      });

    } catch (error) {
      console.error('Ошибка получения подозрительной активности:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });

  // Block user
  app.post('/admin/block-user', async (req, res) => {
    try {
      const { adminKey, userAddress, reason, durationHours } = req.body;
      
      if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Неверный админ ключ' });
      }

      if (!userAddress || !reason) {
        return res.status(400).json({ error: 'Необходимы userAddress и reason' });
      }

      // Нормализуем адрес
      let normalizedAddress: string;
      try {
        normalizedAddress = Address.parse(userAddress).toString();
      } catch (error) {
        return res.status(400).json({ error: 'Неверный формат адреса' });
      }

      const client = await pool.connect();
      try {
        await client.query('BEGIN');

        // Проверяем, нет ли уже активной блокировки
        const existingBlockQuery = `
          SELECT id FROM user_blocks 
          WHERE user_address = $1 AND is_active = TRUE
        `;
        const existingBlock = await client.query(existingBlockQuery, [normalizedAddress]);

        if (existingBlock.rows.length > 0) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: 'Пользователь уже заблокирован' });
        }

        // Создаем блокировку
        let blockedUntil = null;
        if (durationHours && durationHours > 0) {
          blockedUntil = new Date(Date.now() + durationHours * 60 * 60 * 1000);
        }

        await client.query(`
          INSERT INTO user_blocks (user_address, reason, blocked_until, created_by)
          VALUES ($1, $2, $3, 'admin')
        `, [normalizedAddress, reason, blockedUntil]);

        // Деактивируем все активные сессии пользователя
        await client.query(`
          UPDATE listening_sessions 
          SET is_active = FALSE 
          WHERE user_address = $1 AND is_active = TRUE
        `, [normalizedAddress]);

        await client.query('COMMIT');

        console.log('🚫 Пользователь заблокирован:', {
          address: normalizedAddress,
          reason,
          blockedUntil: blockedUntil?.toISOString() || 'permanent'
        });

        res.json({
          success: true,
          userAddress: normalizedAddress,
          reason,
          blockedUntil: blockedUntil?.toISOString() || null,
          message: 'Пользователь заблокирован успешно'
        });

      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      console.error('Ошибка блокировки пользователя:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });

  // Unblock user
  app.post('/admin/unblock-user', async (req, res) => {
    try {
      const { adminKey, userAddress } = req.body;
      
      if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Неверный админ ключ' });
      }

      if (!userAddress) {
        return res.status(400).json({ error: 'Необходим userAddress' });
      }

      // Нормализуем адрес
      let normalizedAddress: string;
      try {
        normalizedAddress = Address.parse(userAddress).toString();
      } catch (error) {
        return res.status(400).json({ error: 'Неверный формат адреса' });
      }

      const result = await pool.query(`
        UPDATE user_blocks 
        SET is_active = FALSE, resolved_at = NOW()
        WHERE user_address = $1 AND is_active = TRUE
        RETURNING id
      `, [normalizedAddress]);

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Активная блокировка не найдена' });
      }

      console.log('✅ Пользователь разблокирован:', normalizedAddress);

      res.json({
        success: true,
        userAddress: normalizedAddress,
        message: 'Пользователь разблокирован успешно'
      });

    } catch (error) {
      console.error('Ошибка разблокировки пользователя:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });

  // Manual sync
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

  // Cleanup old data
  app.post('/admin/cleanup', async (req, res) => {
    try {
      const { adminKey } = req.body;
      
      if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: 'Неверный админ ключ' });
      }

      console.log('🧹 Начинаем очистку старых данных...');

      const client = await pool.connect();
      try {
        // Запускаем функцию очистки
        await client.query('SELECT cleanup_expired_sessions()');

        // Получаем статистику очистки
        const statsQuery = `
          SELECT 
            (SELECT COUNT(*) FROM listening_sessions WHERE is_active = FALSE) as inactive_sessions,
            (SELECT COUNT(*) FROM suspicious_activities WHERE is_resolved = TRUE) as resolved_activities,
            (SELECT COUNT(*) FROM user_blocks WHERE is_active = FALSE) as inactive_blocks
        `;

        const stats = await client.query(statsQuery);

        console.log('✅ Очистка завершена');

        res.json({
          success: true,
          message: 'Очистка завершена успешно',
          stats: {
            inactiveSessions: parseInt(stats.rows[0].inactive_sessions) || 0,
            resolvedActivities: parseInt(stats.rows[0].resolved_activities) || 0,
            inactiveBlocks: parseInt(stats.rows[0].inactive_blocks) || 0
          }
        });

      } finally {
        client.release();
      }

    } catch (error) {
      console.error('Ошибка очистки данных:', error);
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });
}