import { Address } from '@ton/core';
import { pool } from '../database/database';
import { tonapi } from './tonapi';
import * as fs from 'fs';
import * as path from 'path';

// Load whitelist
const whitelistPath = path.join(__dirname, '../whitelist.json');
const whitelist = JSON.parse(fs.readFileSync(whitelistPath, 'utf-8')).collections;

// Global sync status tracking
let lastSyncTime: Date | null = null;
let syncInProgress = false;

export function getLastSyncTime(): Date | null {
  return lastSyncTime;
}

export function getSyncInProgress(): boolean {
  return syncInProgress;
}

export async function syncCollectionsFromWhitelist() {
  console.log('🔄 Синхронизация коллекций из whitelist...');
  let syncedCount = 0;
  
  for (let collectionAddressString of whitelist) {
    try {
      // Parse address to validate format
      const parsedAddress = Address.parse(collectionAddressString).toString();
      const collectionAddress = parsedAddress.toString(); // Convert back to string for database
      
      // Get collection info from TON API
      const collectionInfo = await tonapi.nft.getNftCollection(parsedAddress);
      
      const client = await pool.connect();
      try {
        await client.query(`
          INSERT INTO collections (address, name, image, description, updated_at)
          VALUES ($1, $2, $3, $4, NOW())
          ON CONFLICT (address) 
          DO UPDATE SET 
            name = EXCLUDED.name,
            image = EXCLUDED.image,
            description = EXCLUDED.description,
            updated_at = NOW()
        `, [
          collectionAddress,
          collectionInfo.metadata?.name || `Collection ${collectionAddress.slice(-6)}`,
          collectionInfo.metadata?.image || null,
          collectionInfo.metadata?.description || null
        ]);
        
        syncedCount++;
        console.log(`✅ Коллекция синхронизирована: ${collectionInfo.metadata?.name || collectionAddress}`);
      } catch (dbError) {
        console.error(`❌ Ошибка сохранения коллекции ${collectionAddress}:`, dbError);
      } finally {
        client.release();
      }
    } catch (apiError) {
      console.error(`⚠️ Ошибка получения данных коллекции ${collectionAddressString}:`, apiError);
      
      // If we can't get data from API, create basic record
      const client = await pool.connect();
      try {
        // Parse address for basic record too
        const parsedAddress = Address.parse(collectionAddressString);
        const collectionAddress = parsedAddress.toString();
        
        await client.query(`
          INSERT INTO collections (address, name, description, updated_at)
          VALUES ($1, $2, $3, NOW())
          ON CONFLICT (address) DO UPDATE SET updated_at = NOW()
        `, [
          collectionAddress,
          `Collection ${collectionAddress.slice(-6)}`,
          'NFT коллекция'
        ]);
        syncedCount++;
        console.log(`✅ Создана базовая запись для коллекции: ${collectionAddress}`);
      } catch (dbError) {
        console.error(`❌ Ошибка создания базовой записи коллекции ${collectionAddressString}:`, dbError);
      } finally {
        client.release();
      }
    }

    // Small delay between requests to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  
  console.log(`✅ Синхронизировано ${syncedCount} коллекций`);
}

export async function syncNFTsFromCollection(collectionAddress: string, limit: number = 100) {
  console.log(`🔄 Синхронизация NFT для коллекции ${collectionAddress}...`);
  
  try {
    const client = await pool.connect();
    try {
      // Создаем базовую запись коллекции если её нет
      await client.query(`
        INSERT INTO collections (address, name, description, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (address) DO UPDATE SET updated_at = NOW()
      `, [
        collectionAddress,
        `Collection ${collectionAddress.slice(-6)}`,
        'NFT коллекция из whitelist'
      ]);
      
      console.log(`✅ Базовая запись создана для коллекции ${collectionAddress}`);
    } finally {
      client.release();
    }
    
    console.log(`ℹ️ NFT будут добавлены в базу данных при первых прослушиваниях`);
  } catch (error) {
    console.error(`❌ Ошибка создания базовой записи для коллекции ${collectionAddress}:`, error);
  }
}

export async function performFullSync() {
  if (syncInProgress) {
    console.log('⏳ Синхронизация уже выполняется, пропускаем...');
    return;
  }

  syncInProgress = true;
  console.log('🚀 Начинаем полную синхронизацию данных...');
  
  try {
    // First sync collections
    await syncCollectionsFromWhitelist();
    
    // Then sync NFTs for each collection
    for (const collectionAddress of whitelist) {
      await syncNFTsFromCollection(collectionAddress, 200);
      // Pause between collections
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    lastSyncTime = new Date();
    console.log('✅ Полная синхронизация завершена успешно');
  } catch (error) {
    console.error('❌ Ошибка при полной синхронизации:', error);
  } finally {
    syncInProgress = false;
  }
}