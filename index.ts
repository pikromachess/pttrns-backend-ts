import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv';
import { initializeDatabase, pool } from './database/database';
import { setupRoutes } from './routes/routes';
import { setupMiddleware } from './middleware/middleware';
import { performFullSync } from './services/syncService';

dotenv.config();

const app = express();

// Настройка базовой конфигурации
app.set('trust proxy', process.env.NODE_ENV === 'production' ? 1 : false);

// ИСПРАВЛЕНО: Настройка CORS с правильными заголовками
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:3000',
    'https://pikromachess-pttrns-frontend-dc0f.twc1.net',
    'https://pttrns-frontend.vercel.app'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  exposedHeaders: ['Content-Length', 'X-Foo', 'X-Bar'],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// Дополнительная обработка preflight запросов
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Настройка middleware
setupMiddleware(app);

// Настройка роутов
setupRoutes(app);

// Health check
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    
    res.json({
      status: 'healthy',
      database: 'connected',
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

// Главная страница
app.get('/', (req, res) => {
  res.json({
    name: 'NFT Music Backend',
    version: '1.0.0',
    status: 'running',
    cors: {
      enabled: true,
      origins: corsOptions.origin
    },
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
      sessions: [
        'POST /api/session/create',
        'POST /api/session/validate',
        'POST /api/session-listens',
        'GET /api/session/user-stats'
      ],
      admin: [
        'GET /admin/sessions-stats',
        'GET /admin/suspicious-activities',
        'POST /admin/block-user',
        'POST /admin/unblock-user',
        'POST /admin/sync',
        'POST /admin/cleanup'
      ]
    }
  });
});

// Глобальный обработчик ошибок
app.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('❌ Глобальная ошибка:', error);
  
  // Не показываем детали ошибки в продакшене
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  res.status(error.status || 500).json({
    error: 'Внутренняя ошибка сервера',
    message: isDevelopment ? error.message : 'Что-то пошло не так',
    ...(isDevelopment && { stack: error.stack })
  });
});

// 404 обработчик
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Эндпоинт не найден',
    path: req.originalUrl,
    method: req.method
  });
});

// Инициализация приложения
async function initializeApp() {
  try {
    console.log('🚀 Инициализация приложения...');
    
    // Инициализация базы данных
    await initializeDatabase();
    
    // Выполнение начальной синхронизации
    await performFullSync();
    
    // Настройка периодической синхронизации каждые 6 часов
    setInterval(async () => {
      console.log('⏰ Запуск периодической синхронизации...');
      await performFullSync();
    }, 6 * 60 * 60 * 1000);
    
    console.log('✅ Приложение инициализировано успешно');
    
  } catch (error) {
    console.error('❌ Ошибка инициализации приложения:', error);
    throw error;
  }
}

// Запуск сервера
const PORT = process.env.PORT || 3000;

initializeApp()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Сервер запущен на порту ${PORT}`);
      console.log(`📱 Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:5173'}`);
      console.log(`🎵 Music Backend URL: ${process.env.MUSIC_BACKEND_URL || 'http://localhost:8000'}`);
      console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 CORS Origins:`, corsOptions.origin);
    });
  })
  .catch(error => {
    console.error('💥 Критическая ошибка запуска приложения:', error);
    process.exit(1);
  });

export default app;