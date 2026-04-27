const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { logger } = require('../utils/logger');

const dbPath = path.resolve(process.cwd(), process.env.DATABASE_PATH || './data/auth.db');
const schemaPath = path.resolve(process.cwd(), './db/schema.sql');

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

let db;
try {
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(fs.readFileSync(schemaPath, 'utf8'));
} catch (error) {
  logger.error('Database initialization failed', error);
  process.exit(1);
}

function run(fn, fallback = null) {
  try {
    return fn(db);
  } catch (error) {
    logger.error('Database operation failed', error);
    return fallback;
  }
}

module.exports = { db, dbPath, run };
