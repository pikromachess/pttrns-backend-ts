import { Pool } from 'pg';
import * as dotenv from 'dotenv';

dotenv.config();

// Database connection
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false
});

// Database initialization
export async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create main tables
    await createMainTables(client);
    
    // Create session tables
    await createSessionTables(client);
    
    // Create monitoring tables
    await createMonitoringTables(client);
    
    // Create indexes
    await createIndexes(client);
    
    // Create functions and triggers
    await createFunctionsAndTriggers(client);

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

async function createMainTables(client: any) {
  // Collections table
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

  // NFTs table
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

  // Listens table (общая статистика)
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

  // API keys table
  await client.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      key VARCHAR(255) PRIMARY KEY,
      address VARCHAR(200) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP NOT NULL
    )
  `);
}

async function createSessionTables(client: any) {
  // Listening sessions table
  await client.query(`
    CREATE TABLE IF NOT EXISTS listening_sessions (
      session_id VARCHAR(500) PRIMARY KEY,
      user_address VARCHAR(200) NOT NULL,
      signature_data JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP NOT NULL,
      last_activity TIMESTAMP DEFAULT NOW(),
      is_active BOOLEAN DEFAULT TRUE
    )
  `);

  // Session listens table (индивидуальная статистика пользователей)
  await client.query(`
    CREATE TABLE IF NOT EXISTS session_listens (
      id SERIAL PRIMARY KEY,
      user_address VARCHAR(200) NOT NULL,
      nft_address VARCHAR(200) NOT NULL,
      collection_address VARCHAR(200) NOT NULL,
      session_id VARCHAR(500) NOT NULL REFERENCES listening_sessions(session_id),
      count INTEGER DEFAULT 1,
      first_recorded TIMESTAMP DEFAULT NOW(),
      last_recorded TIMESTAMP DEFAULT NOW(),
      UNIQUE(user_address, nft_address)
    )
  `);
}

async function createMonitoringTables(client: any) {
  // Suspicious activities table
  await client.query(`
    CREATE TABLE IF NOT EXISTS suspicious_activities (
      id SERIAL PRIMARY KEY,
      user_address VARCHAR(200) NOT NULL,
      activity_type VARCHAR(100) NOT NULL,
      description TEXT,
      metadata JSONB DEFAULT '{}',
      severity VARCHAR(20) DEFAULT 'low',
      detected_at TIMESTAMP DEFAULT NOW(),
      resolved_at TIMESTAMP NULL,
      is_resolved BOOLEAN DEFAULT FALSE
    )
  `);

  // User blocks table - исправляем UNIQUE constraint
  await client.query(`
    CREATE TABLE IF NOT EXISTS user_blocks (
      id SERIAL PRIMARY KEY,
      user_address VARCHAR(200) NOT NULL,
      reason TEXT NOT NULL,
      blocked_until TIMESTAMP NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      created_by VARCHAR(100) DEFAULT 'system',
      is_active BOOLEAN DEFAULT TRUE
    )
  `);

  // Создаем уникальный частичный индекс отдельно
  await client.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_user_blocks_active_unique 
    ON user_blocks(user_address) 
    WHERE is_active = TRUE
  `);
}

async function createIndexes(client: any) {
  // Main tables indexes
  await client.query(`CREATE INDEX IF NOT EXISTS idx_listens_nft_address ON listens(nft_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_listens_collection_address ON listens(collection_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_listens_count ON listens(count DESC)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_nfts_collection_address ON nfts(collection_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_nfts_index ON nfts(index_number)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_collections_address ON collections(address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_api_keys_address ON api_keys(address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at)`);

  // Session tables indexes
  await client.query(`CREATE INDEX IF NOT EXISTS idx_listening_sessions_user_address ON listening_sessions(user_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_listening_sessions_expires_at ON listening_sessions(expires_at)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_listening_sessions_is_active ON listening_sessions(is_active)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_session_listens_user_address ON session_listens(user_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_session_listens_nft_address ON session_listens(nft_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_session_listens_collection_address ON session_listens(collection_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_session_listens_session_id ON session_listens(session_id)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_session_listens_last_recorded ON session_listens(last_recorded)`);

  // Monitoring tables indexes
  await client.query(`CREATE INDEX IF NOT EXISTS idx_suspicious_activities_user_address ON suspicious_activities(user_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_suspicious_activities_detected_at ON suspicious_activities(detected_at)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_suspicious_activities_is_resolved ON suspicious_activities(is_resolved)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_suspicious_activities_severity ON suspicious_activities(severity)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_user_blocks_user_address ON user_blocks(user_address)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_user_blocks_is_active ON user_blocks(is_active)`);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_user_blocks_blocked_until ON user_blocks(blocked_until)`);
}

async function createFunctionsAndTriggers(client: any) {
  // Cleanup function
  await client.query(`
    CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
    RETURNS void AS $$
    BEGIN
      -- Деактивируем истекшие сессии
      UPDATE listening_sessions 
      SET is_active = FALSE 
      WHERE expires_at < NOW() AND is_active = TRUE;
      
      -- Удаляем старые деактивированные сессии (старше 7 дней)
      DELETE FROM listening_sessions 
      WHERE is_active = FALSE 
      AND expires_at < NOW() - INTERVAL '7 days';
      
      -- Очищаем старые записи подозрительной активности (старше 30 дней)
      DELETE FROM suspicious_activities 
      WHERE detected_at < NOW() - INTERVAL '30 days'
      AND is_resolved = TRUE;
      
      -- Деактивируем истекшие блокировки
      UPDATE user_blocks 
      SET is_active = FALSE 
      WHERE blocked_until < NOW() AND is_active = TRUE;
    END;
    $$ LANGUAGE plpgsql;
  `);

  // Session activity update function
  await client.query(`
    CREATE OR REPLACE FUNCTION update_session_activity()
    RETURNS TRIGGER AS $$
    BEGIN
      UPDATE listening_sessions 
      SET last_activity = NOW() 
      WHERE session_id = NEW.session_id;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
  `);

  // Drop trigger if exists and create new one
  await client.query(`DROP TRIGGER IF EXISTS trigger_update_session_activity ON session_listens`);
  await client.query(`
    CREATE TRIGGER trigger_update_session_activity
      AFTER INSERT ON session_listens
      FOR EACH ROW
      EXECUTE FUNCTION update_session_activity();
  `);
}