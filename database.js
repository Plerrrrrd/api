const Database = require('better-sqlite3');
const CryptoJS = require('crypto-js');
const path = require('path');
const fs = require('fs');

const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

const db = new Database(path.join(dbDir, 'vortex.db'));

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default-secret-key-that-is-long-enough';

// --- Schema Initialization ---
function initializeDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS cloudflare_configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      unique_id TEXT NOT NULL UNIQUE,
      cf_api_token TEXT NOT NULL,
      cf_account_id TEXT NOT NULL,
      cf_zone_id TEXT,
      cf_worker_name TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Add cf_worker_name column if it doesn't exist (for migration)
  try {
    db.prepare('SELECT cf_worker_name FROM cloudflare_configs LIMIT 1').get();
  } catch (e) {
    db.exec('ALTER TABLE cloudflare_configs ADD COLUMN cf_worker_name TEXT');
    console.log('Migrated database: Added cf_worker_name column.');
  }

  console.log('Database and cloudflare_configs table initialized.');
}

// --- Encryption/Decryption ---
function encrypt(text) {
  return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}

function decrypt(ciphertext) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
  return bytes.toString(CryptoJS.enc.Utf8);
}

// --- Database Functions ---
function addCloudflareConfig(unique_id, api_token, account_id, { zone_id, worker_name }) {
  const encryptedToken = encrypt(api_token);
  const stmt = db.prepare(
    'INSERT INTO cloudflare_configs (unique_id, cf_api_token, cf_account_id, cf_zone_id, cf_worker_name) VALUES (?, ?, ?, ?, ?)'
  );
  try {
    stmt.run(unique_id, encryptedToken, account_id, zone_id, worker_name);
    return { success: true };
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return { success: false, error: 'Unique ID already exists.' };
    }
    console.error('Failed to add Cloudflare config:', error);
    return { success: false, error: 'Database error' };
  }
}

function getCloudflareConfig(unique_id) {
  try {
    const stmt = db.prepare('SELECT * FROM cloudflare_configs WHERE unique_id = ?');
    const row = stmt.get(unique_id);
    if (!row) {
      return null;
    }
    return {
      ...row,
      cf_api_token: decrypt(row.cf_api_token),
    };
  } catch (error) {
    console.error('Failed to get Cloudflare config:', error);
    return null;
  }
}

module.exports = {
  initializeDatabase,
  addCloudflareConfig,
  getCloudflareConfig,
};