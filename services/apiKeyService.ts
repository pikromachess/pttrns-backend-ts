import { pool } from '../database/database';
import { Address } from '@ton/core';

export async function saveApiKey(apiKey: string, address: string, created: Date, expires: Date) {
  const client = await pool.connect();
  const normalizedAddress = Address.parse(address).toString();
  try {
    await client.query('BEGIN');
    
    // Delete old user keys (including expired ones)
    await client.query(
      'DELETE FROM api_keys WHERE address = $1 OR expires_at < NOW()',
      [normalizedAddress]
    );
    
    // Create new key
    await client.query(
      'INSERT INTO api_keys (key, address, created_at, expires_at) VALUES ($1, $2, $3, $4)',
      [apiKey, normalizedAddress, created, expires]
    );
    
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function validateApiKey(apiKey: string) {
  const result = await pool.query('SELECT * FROM api_keys WHERE key = $1', [apiKey]);
  const keyData = result.rows[0];
  if (!keyData || new Date() > new Date(keyData.expires_at)) {
    if (keyData) await pool.query('DELETE FROM api_keys WHERE key = $1', [apiKey]);
    return null;
  }
  return { address: keyData.address, expires: new Date(keyData.expires_at) };
}