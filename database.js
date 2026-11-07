const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

let dbInstance = null;

/**
 * Initializes and returns the SQLite database connection.
 * @param {string} [customPath] - Optional custom path for test databases.
 * @returns {Database.Database}
 */
function getDatabase(customPath = null) {
  const dataDir = process.env.DATA_DIR || path.join(__dirname, '../data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  const dbPath = customPath || path.join(dataDir, 'trustvault.db');

  if (dbInstance && dbInstance.name === dbPath && !dbInstance.readonly) {
    return dbInstance;
  }

  if (dbInstance) {
    try { dbInstance.close(); } catch (e) {}
  }

  const db = new Database(dbPath);

  // Enable WAL mode & Foreign Key constraints
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Initialize Schema
  initSchema(db);

  dbInstance = db;
  return db;
}

/**
 * Creates database tables and indices if they do not exist.
 * @param {Database.Database} db
 */
function initSchema(db) {
  db.exec(`
    -- Users Table
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'OWNER' CHECK(role IN ('ADMIN', 'OWNER', 'VIEWER')),
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'DISABLED')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login_at DATETIME
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

    -- Documents Table
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      category TEXT NOT NULL DEFAULT 'General',
      file_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      storage_key TEXT NOT NULL UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
    CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);

    -- Document Permissions Table
    CREATE TABLE IF NOT EXISTS document_permissions (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      permission_type TEXT NOT NULL CHECK(permission_type IN ('READ', 'EDIT')),
      granted_by TEXT NOT NULL,
      granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      revoked_at DATETIME,
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED')),
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (granted_by) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_doc_perm_doc_user ON document_permissions(document_id, user_id);
    CREATE INDEX IF NOT EXISTS idx_doc_perm_user ON document_permissions(user_id);

    -- Audit Logs Table (Tamper-Evident Hash Chain)
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      document_id TEXT,
      action TEXT NOT NULL,
      result TEXT NOT NULL DEFAULT 'SUCCESS' CHECK(result IN ('SUCCESS', 'FAILURE', 'WARNING')),
      ip_address TEXT,
      metadata TEXT DEFAULT '{}',
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      previous_hash TEXT NOT NULL,
      event_hash TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_document ON audit_logs(document_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
  `);
}

module.exports = {
  getDatabase
};
