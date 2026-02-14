const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');

let db;

function open() {
  if (db) return db;
  db = new sqlite3.Database(DB_PATH);
  return db;
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    open().run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    open().get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    open().all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function init() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      failed_attempts INTEGER DEFAULT 0,
      locked_until INTEGER,
      updated_at INTEGER,
      UNIQUE(email, ip_address)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL UNIQUE,
      token_hash TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked BOOLEAN DEFAULT FALSE,
      refresh_count INTEGER DEFAULT 0,
      last_refresh_at INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Add columns if not exists (for existing dbs)
  try {
    await run(`ALTER TABLE refresh_tokens ADD COLUMN session_id TEXT`);
  } catch (err) {}
  try {
    await run(`ALTER TABLE refresh_tokens ADD COLUMN token_hash TEXT`);
  } catch (err) {}
  try {
    await run(`ALTER TABLE refresh_tokens ADD COLUMN revoked BOOLEAN DEFAULT FALSE`);
  } catch (err) {}
  try {
    await run(`ALTER TABLE refresh_tokens ADD COLUMN refresh_count INTEGER DEFAULT 0`);
  } catch (err) {}
  try {
    await run(`ALTER TABLE refresh_tokens ADD COLUMN last_refresh_at INTEGER`);
  } catch (err) {}
  // Rename token_id to session_id if exists
  try {
    await run(`ALTER TABLE refresh_tokens RENAME COLUMN token_id TO session_id`);
  } catch (err) {}

  await run(`CREATE INDEX IF NOT EXISTS idx_login_attempts_email_ip ON login_attempts(email, ip_address)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)`);
  await run(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at)`);

  // Cleanup old revoked/expired refresh tokens.
  const now = Math.floor(Date.now() / 1000);
  const thirtyDaysAgo = now - (30 * 24 * 60 * 60);
  await run(`DELETE FROM refresh_tokens WHERE (revoked = TRUE OR expires_at < ?) AND created_at < datetime(?, 'unixepoch')`, [now, thirtyDaysAgo]);


}

module.exports = {
  open,
  run,
  get,
  all,
  init,
};