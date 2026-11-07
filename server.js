require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const Database = require('better-sqlite3');
const crypto = require('crypto');

/**
 * TrustVault - Complete Self-Contained Enterprise Server
 * Handles directory permissions gracefully to prevent EACCES errors on cloud platforms.
 */

// ============================================================================
// 1. DATABASE & CONFIGURATION
// ============================================================================
let dbInstance = null;

function getDatabase(customPath = null) {
  let dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');

  // Defensive Directory Creation (Graceful fallback if /var/data permission is denied)
  try {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
  } catch (err) {
    console.warn(`[TrustVault Storage Warning]: Cannot create '${dataDir}' (${err.message}). Falling back to local './data' directory.`);
    dataDir = path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
  }

  const dbPath = customPath || path.join(dataDir, 'trustvault.db');

  if (dbInstance && dbInstance.name === dbPath && !dbInstance.readonly) {
    return dbInstance;
  }

  if (dbInstance) {
    try { dbInstance.close(); } catch (e) {}
  }

  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Initialize Tables
  db.exec(`
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

  dbInstance = db;
  return db;
}

// ============================================================================
// 2. AUDIT LOGGING & STORAGE SERVICES
// ============================================================================
const GENESIS_HASH = '0'.repeat(64);

function calculateEventHash(payload, secret) {
  const data = [
    payload.id || '',
    payload.userId || '',
    payload.documentId || '',
    payload.action || '',
    payload.result || 'SUCCESS',
    payload.ipAddress || '',
    typeof payload.metadata === 'string' ? payload.metadata : JSON.stringify(payload.metadata || {}),
    payload.timestamp || '',
    payload.previousHash || GENESIS_HASH
  ].join('|');

  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function logEvent(db, { userId = null, documentId = null, action, result = 'SUCCESS', ipAddress = '', metadata = {} }) {
  const auditSecret = process.env.TRUSTVAULT_AUDIT_SECRET || 'trustvault-default-audit-secret-key';

  const lastLog = db.prepare('SELECT event_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1').get();
  const previousHash = lastLog ? lastLog.event_hash : GENESIS_HASH;

  const id = uuidv4();
  const timestamp = new Date().toISOString();
  const metadataStr = typeof metadata === 'string' ? metadata : JSON.stringify(metadata);

  const eventHash = calculateEventHash({
    id, userId, documentId, action, result, ipAddress, metadata: metadataStr, timestamp, previousHash
  }, auditSecret);

  const stmt = db.prepare(`
    INSERT INTO audit_logs (id, user_id, document_id, action, result, ip_address, metadata, timestamp, previous_hash, event_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(id, userId, documentId, action, result, ipAddress, metadataStr, timestamp, previousHash, eventHash);

  return { id, userId, documentId, action, result, ipAddress, metadata: metadataStr, timestamp, previousHash, eventHash };
}

function verifyAuditChain(db) {
  const auditSecret = process.env.TRUSTVAULT_AUDIT_SECRET || 'trustvault-default-audit-secret-key';
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY rowid ASC').all();

  let expectedPreviousHash = GENESIS_HASH;

  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];

    if (log.previous_hash !== expectedPreviousHash) {
      return {
        valid: false,
        totalLogs: logs.length,
        tamperedAt: { id: log.id, index: i, reason: `Previous hash mismatch. Expected ${expectedPreviousHash}, found ${log.previous_hash}` }
      };
    }

    const recomputedHash = calculateEventHash({
      id: log.id,
      userId: log.user_id,
      documentId: log.document_id,
      action: log.action,
      result: log.result,
      ipAddress: log.ip_address,
      metadata: log.metadata,
      timestamp: log.timestamp,
      previousHash: log.previous_hash
    }, auditSecret);

    if (recomputedHash !== log.event_hash) {
      return {
        valid: false,
        totalLogs: logs.length,
        tamperedAt: { id: log.id, index: i, reason: `Event hash mismatch. Recomputed ${recomputedHash}, found ${log.event_hash}` }
      };
    }

    expectedPreviousHash = log.event_hash;
  }

  return { valid: true, totalLogs: logs.length };
}

function getStorageDir() {
  let storageDir = process.env.STORAGE_DIR || path.join(__dirname, 'storage');
  try {
    if (!fs.existsSync(storageDir)) {
      fs.mkdirSync(storageDir, { recursive: true });
    }
  } catch (err) {
    console.warn(`[TrustVault Storage Warning]: Cannot create '${storageDir}' (${err.message}). Falling back to local './storage' directory.`);
    storageDir = path.join(__dirname, 'storage');
    if (!fs.existsSync(storageDir)) {
      fs.mkdirSync(storageDir, { recursive: true });
    }
  }
  return storageDir;
}

function saveFile(buffer, originalName) {
  const storageDir = getStorageDir();
  const safeFilename = path.basename(originalName).replace(/[^a-zA-Z0-9._-]/g, '_');
  const storageKey = `${uuidv4()}_${safeFilename}`;
  const targetPath = path.join(storageDir, storageKey);

  fs.writeFileSync(targetPath, buffer);
  return storageKey;
}

function getFilePath(storageKey) {
  if (!storageKey || storageKey.includes('..') || storageKey.includes('/') || storageKey.includes('\\')) {
    return null;
  }
  const storageDir = getStorageDir();
  const filePath = path.join(storageDir, storageKey);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return filePath;
}

function deleteFile(storageKey) {
  const filePath = getFilePath(storageKey);
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    return true;
  }
  return false;
}

// ============================================================================
// 3. MIDDLEWARE & UPLOAD
// ============================================================================
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }

  const db = getDatabase();
  const user = db.prepare('SELECT id, name, email, role, status, created_at, last_login_at FROM users WHERE id = ?').get(req.session.userId);

  if (!user) {
    req.session.destroy();
    return res.status(401).json({ error: 'User account no longer exists.' });
  }

  if (user.status === 'DISABLED') {
    logEvent(db, {
      userId: user.id,
      action: 'DISABLED_ACCOUNT_ACCESS_ATTEMPT',
      result: 'FAILURE',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { path: req.originalUrl }
    });

    req.session.destroy();
    return res.status(403).json({ error: 'Your account has been disabled by an administrator.' });
  }

  req.user = user;
  next();
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      const db = getDatabase();
      logEvent(db, {
        userId: req.user.id,
        action: 'UNAUTHORIZED_ROLE_ACCESS_ATTEMPT',
        result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress,
        metadata: { userRole: req.user.role, requiredRoles: allowedRoles, path: req.originalUrl }
      });

      return res.status(403).json({
        error: `Forbidden: Access restricted to [${allowedRoles.join(', ')}] roles.`
      });
    }

    next();
  };
}

function requireDocumentPermission(requiredLevel = 'READ') {
  return (req, res, next) => {
    const docId = req.params.id || req.params.documentId;
    if (!docId) {
      return res.status(400).json({ error: 'Document ID is required.' });
    }

    const db = getDatabase();
    const document = db.prepare('SELECT * FROM documents WHERE id = ?').get(docId);

    if (!document) {
      return res.status(404).json({ error: 'Document not found.' });
    }

    req.document = document;
    const userId = req.user.id;
    const userRole = req.user.role;

    if (document.owner_id === userId) {
      req.accessLevel = 'OWNER';
      return next();
    }

    if (userRole === 'ADMIN') {
      req.accessLevel = 'ADMIN';
      return next();
    }

    if (requiredLevel === 'OWNER') {
      logEvent(db, {
        userId, documentId: docId, action: 'UNAUTHORIZED_OWNER_ACTION_ATTEMPT', result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress, metadata: { requiredLevel, path: req.originalUrl }
      });
      return res.status(403).json({ error: 'Forbidden: Only the document owner can perform this action.' });
    }

    const activePerm = db.prepare(`
      SELECT permission_type, status
      FROM document_permissions
      WHERE document_id = ? AND user_id = ? AND status = 'ACTIVE'
    `).get(docId, userId);

    if (!activePerm) {
      logEvent(db, {
        userId, documentId: docId, action: 'UNAUTHORIZED_DOCUMENT_ACCESS_ATTEMPT', result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress, metadata: { requiredLevel, path: req.originalUrl }
      });
      return res.status(403).json({ error: 'Forbidden: You do not have permission to access this document.' });
    }

    if (requiredLevel === 'EDIT' && activePerm.permission_type !== 'EDIT') {
      logEvent(db, {
        userId, documentId: docId, action: 'UNAUTHORIZED_DOCUMENT_EDIT_ATTEMPT', result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress, metadata: { userPermission: activePerm.permission_type, requiredLevel }
      });
      return res.status(403).json({ error: 'Forbidden: You need EDIT permission to perform this action.' });
    }

    req.accessLevel = activePerm.permission_type;
    next();
  };
}

const ALLOWED_EXTENSIONS = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.png', '.jpg', '.jpeg', '.zip', '.csv', '.json', '.md'];
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return cb(new Error(`Invalid file type (${ext}).`), false);
    }
    cb(null, true);
  }
});

// ============================================================================
// 4. EXPRESS SERVER SETUP
// ============================================================================
const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, message: { error: 'Too many requests, try again later.' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many login attempts, try again later.' } });

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionSecret = process.env.TRUSTVAULT_SESSION_SECRET || 'trustvault-default-session-secret-change-in-production';
app.use(session({
  name: 'trustvault.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Serve static frontend files
const publicDir = fs.existsSync(path.join(__dirname, 'public')) ? path.join(__dirname, 'public') : __dirname;
app.use(express.static(publicDir));

// ============================================================================
// 5. REST API ENDPOINTS
// ============================================================================

// AUTH ROUTES
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { name, email, password, confirmPassword } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Full Name is required.' });
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'A valid Email Address is required.' });
    if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    if (password !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });

    const db = getDatabase();
    const normalizedEmail = email.trim().toLowerCase();

    const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = ?').get(normalizedEmail);
    if (existing) return res.status(409).json({ error: 'An account with this email address already exists.' });

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = uuidv4();

    db.prepare("INSERT INTO users (id, name, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'OWNER', 'ACTIVE')")
      .run(userId, name.trim(), normalizedEmail, passwordHash);

    logEvent(db, {
      userId, action: 'USER_REGISTER', result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { name: name.trim(), email: normalizedEmail, assignedRole: 'OWNER' }
    });

    res.status(201).json({ message: 'Registration successful! You can now log in.', userId });
  } catch (err) { next(err); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    const db = getDatabase();
    const normalizedEmail = email.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(normalizedEmail);

    if (!user) {
      logEvent(db, { action: 'USER_LOGIN_FAILED', result: 'FAILURE', ipAddress: req.ip, metadata: { email: normalizedEmail, reason: 'Invalid email' } });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      logEvent(db, { userId: user.id, action: 'USER_LOGIN_FAILED', result: 'FAILURE', ipAddress: req.ip, metadata: { email: normalizedEmail, reason: 'Incorrect password' } });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.status === 'DISABLED') {
      logEvent(db, { userId: user.id, action: 'DISABLED_ACCOUNT_LOGIN_ATTEMPT', result: 'FAILURE', ipAddress: req.ip, metadata: { email: normalizedEmail } });
      return res.status(403).json({ error: 'Your account has been disabled. Please contact an administrator.' });
    }

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(new Date().toISOString(), user.id);

      logEvent(db, { userId: user.id, action: 'USER_LOGIN_SUCCESS', result: 'SUCCESS', ipAddress: req.ip, metadata: { email: normalizedEmail, role: user.role } });
      res.json({ message: 'Login successful.', user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } });
    });
  } catch (err) { next(err); }
});

app.post('/api/auth/logout', requireAuth, (req, res, next) => {
  const db = getDatabase();
  logEvent(db, { userId: req.user.id, action: 'USER_LOGOUT', result: 'SUCCESS', ipAddress: req.ip });

  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully.' });
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: req.user }));

// ADMIN ROUTES
app.get('/api/admin/dashboard', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const activeUsers = db.prepare("SELECT COUNT(*) as count FROM users WHERE status = 'ACTIVE'").get().count;
    const disabledUsers = db.prepare("SELECT COUNT(*) as count FROM users WHERE status = 'DISABLED'").get().count;
    const totalDocs = db.prepare('SELECT COUNT(*) as count FROM documents').get().count;
    const totalStorageBytes = db.prepare('SELECT SUM(file_size) as total FROM documents').get().total || 0;
    const totalSharedDocs = db.prepare("SELECT COUNT(DISTINCT document_id) as count FROM document_permissions WHERE status = 'ACTIVE'").get().count;
    const totalPermissions = db.prepare("SELECT COUNT(*) as count FROM document_permissions WHERE status = 'ACTIVE'").get().count;
    const securityEventsCount = db.prepare("SELECT COUNT(*) as count FROM audit_logs WHERE result = 'FAILURE' OR action LIKE 'UNAUTHORIZED%' OR action LIKE 'DISABLED%'").get().count;

    const rolesBreakdown = db.prepare('SELECT role, COUNT(*) as count FROM users GROUP BY role').all();
    const recentActivity = db.prepare(`
      SELECT a.id, a.action, a.result, a.timestamp, a.ip_address, u.name as user_name, u.email as user_email, d.name as document_name
      FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id LEFT JOIN documents d ON a.document_id = d.id
      ORDER BY a.timestamp DESC LIMIT 10
    `).all();

    const recentUploads = db.prepare(`
      SELECT d.id, d.name, d.category, d.file_type, d.file_size, d.created_at, u.name as owner_name
      FROM documents d JOIN users u ON d.owner_id = u.id ORDER BY d.created_at DESC LIMIT 5
    `).all();

    res.json({ stats: { totalUsers, activeUsers, disabledUsers, totalDocs, totalStorageBytes, totalSharedDocs, totalPermissions, securityEventsCount }, rolesBreakdown, recentActivity, recentUploads });
  } catch (err) { next(err); }
});

app.get('/api/admin/users', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const { search, role, status } = req.query;
    const db = getDatabase();
    let query = 'SELECT id, name, email, role, status, created_at, last_login_at FROM users WHERE 1=1';
    const params = [];

    if (search) { query += ' AND (LOWER(name) LIKE ? OR LOWER(email) LIKE ?)'; params.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`); }
    if (role) { query += ' AND role = ?'; params.push(role); }
    if (status) { query += ' AND status = ?'; params.push(status); }

    query += ' ORDER BY created_at DESC';
    res.json({ users: db.prepare(query).all(...params) });
  } catch (err) { next(err); }
});

app.patch('/api/admin/users/:id/role', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const { role } = req.body;
    const targetUserId = req.params.id;
    if (!['ADMIN', 'OWNER', 'VIEWER'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });

    const db = getDatabase();
    const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(targetUserId);
    if (!targetUser) return res.status(404).json({ error: 'User not found.' });

    if (targetUser.role === 'ADMIN' && role !== 'ADMIN') {
      const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'").get().count;
      if (adminCount <= 1) return res.status(400).json({ error: 'Cannot demote the last remaining active Administrator.' });
    }

    db.prepare("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(role, targetUserId);
    logEvent(db, { userId: req.user.id, action: 'ADMIN_ROLE_CHANGE', result: 'SUCCESS', ipAddress: req.ip, metadata: { targetUserId, targetUserEmail: targetUser.email, oldRole: targetUser.role, newRole: role } });

    res.json({ message: `Role updated to ${role} successfully.` });
  } catch (err) { next(err); }
});

app.patch('/api/admin/users/:id/status', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const { status } = req.body;
    const targetUserId = req.params.id;
    if (!['ACTIVE', 'DISABLED'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });

    const db = getDatabase();
    const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(targetUserId);
    if (!targetUser) return res.status(404).json({ error: 'User not found.' });

    if (targetUser.role === 'ADMIN' && status === 'DISABLED') {
      const activeAdminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'").get().count;
      if (activeAdminCount <= 1) return res.status(400).json({ error: 'Cannot disable the last remaining active Administrator.' });
    }

    db.prepare("UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(status, targetUserId);
    logEvent(db, { userId: req.user.id, action: 'ADMIN_STATUS_CHANGE', result: 'SUCCESS', ipAddress: req.ip, metadata: { targetUserId, targetUserEmail: targetUser.email, oldStatus: targetUser.status, newStatus: status } });

    res.json({ message: `User status updated to ${status} successfully.` });
  } catch (err) { next(err); }
});

app.get('/api/admin/documents', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    const documents = db.prepare(`
      SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at,
             u.id as owner_id, u.name as owner_name, u.email as owner_email,
             (SELECT COUNT(*) FROM document_permissions dp WHERE dp.document_id = d.id AND dp.status = 'ACTIVE') as active_shares_count
      FROM documents d JOIN users u ON d.owner_id = u.id ORDER BY d.created_at DESC
    `).all();
    res.json({ documents });
  } catch (err) { next(err); }
});

app.get('/api/admin/security-events', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    const events = db.prepare(`
      SELECT a.id, a.user_id, a.action, a.result, a.ip_address, a.metadata, a.timestamp, u.name as user_name, u.email as user_email
      FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id
      WHERE a.result = 'FAILURE' OR a.action LIKE 'UNAUTHORIZED%' OR a.action LIKE 'DISABLED%' OR a.action LIKE 'ADMIN%'
      ORDER BY a.timestamp DESC LIMIT 100
    `).all();
    res.json({ events });
  } catch (err) { next(err); }
});

// OWNER ROUTES
app.get('/api/owner/dashboard', requireAuth, requireRole('OWNER', 'ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    const ownerId = req.user.id;

    const myTotalDocs = db.prepare('SELECT COUNT(*) as count FROM documents WHERE owner_id = ?').get(ownerId).count;
    const storageUsedBytes = db.prepare('SELECT SUM(file_size) as total FROM documents WHERE owner_id = ?').get(ownerId).total || 0;
    const totalSharedWithOthers = db.prepare("SELECT COUNT(DISTINCT dp.document_id) as count FROM document_permissions dp JOIN documents d ON dp.document_id = d.id WHERE d.owner_id = ? AND dp.status = 'ACTIVE'").get(ownerId).count;
    const activePermissionsCount = db.prepare("SELECT COUNT(*) as count FROM document_permissions dp JOIN documents d ON dp.document_id = d.id WHERE d.owner_id = ? AND dp.status = 'ACTIVE'").get(ownerId).count;

    const recentDocs = db.prepare("SELECT d.id, d.name, d.category, d.file_type, d.file_size, d.created_at, (SELECT COUNT(*) FROM document_permissions dp WHERE dp.document_id = d.id AND dp.status = 'ACTIVE') as shared_count FROM documents d WHERE d.owner_id = ? ORDER BY d.created_at DESC LIMIT 5").all(ownerId);
    const recentShares = db.prepare("SELECT dp.id, dp.permission_type, dp.granted_at, dp.status, d.name as document_name, u.name as target_user_name, u.email as target_user_email FROM document_permissions dp JOIN documents d ON dp.document_id = d.id JOIN users u ON dp.user_id = u.id WHERE d.owner_id = ? ORDER BY dp.granted_at DESC LIMIT 5").all(ownerId);

    res.json({ stats: { myTotalDocs, storageUsedBytes, totalSharedWithOthers, activePermissionsCount }, recentDocs, recentShares });
  } catch (err) { next(err); }
});

app.get('/api/owner/documents', requireAuth, requireRole('OWNER', 'ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    const documents = db.prepare("SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, d.updated_at, (SELECT COUNT(*) FROM document_permissions dp WHERE dp.document_id = d.id AND dp.status = 'ACTIVE') as shared_count FROM documents d WHERE d.owner_id = ? ORDER BY d.created_at DESC").all(req.user.id);
    res.json({ documents });
  } catch (err) { next(err); }
});

app.get('/api/owner/permissions', requireAuth, requireRole('OWNER', 'ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    const permissions = db.prepare("SELECT dp.id, dp.document_id, dp.user_id, dp.permission_type, dp.granted_at, dp.revoked_at, dp.status, d.name as document_name, u.name as user_name, u.email as user_email FROM document_permissions dp JOIN documents d ON dp.document_id = d.id JOIN users u ON dp.user_id = u.id WHERE d.owner_id = ? ORDER BY dp.granted_at DESC").all(req.user.id);
    res.json({ permissions });
  } catch (err) { next(err); }
});

app.get('/api/owner/activity', requireAuth, requireRole('OWNER', 'ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    const activity = db.prepare("SELECT a.id, a.action, a.result, a.timestamp, a.metadata, d.name as document_name FROM audit_logs a LEFT JOIN documents d ON a.document_id = d.id WHERE a.user_id = ? OR d.owner_id = ? ORDER BY a.timestamp DESC LIMIT 50").all(req.user.id, req.user.id);
    res.json({ activity });
  } catch (err) { next(err); }
});

// VIEWER ROUTES
app.get('/api/viewer/dashboard', requireAuth, (req, res, next) => {
  try {
    const db = getDatabase();
    const userId = req.user.id;

    const totalSharedDocs = db.prepare("SELECT COUNT(*) as count FROM document_permissions WHERE user_id = ? AND status = 'ACTIVE'").get(userId).count;
    const readOnlyDocs = db.prepare("SELECT COUNT(*) as count FROM document_permissions WHERE user_id = ? AND status = 'ACTIVE' AND permission_type = 'READ'").get(userId).count;
    const editableDocs = db.prepare("SELECT COUNT(*) as count FROM document_permissions WHERE user_id = ? AND status = 'ACTIVE' AND permission_type = 'EDIT'").get(userId).count;

    const sharedDocuments = db.prepare("SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, dp.permission_type, dp.granted_at, u.name as owner_name, u.email as owner_email FROM document_permissions dp JOIN documents d ON dp.document_id = d.id JOIN users u ON d.owner_id = u.id WHERE dp.user_id = ? AND dp.status = 'ACTIVE' ORDER BY dp.granted_at DESC").all(userId);

    res.json({ stats: { totalSharedDocs, readOnlyDocs, editableDocs }, sharedDocuments });
  } catch (err) { next(err); }
});

app.get('/api/viewer/documents', requireAuth, (req, res, next) => {
  try {
    const db = getDatabase();
    const documents = db.prepare("SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, dp.permission_type, dp.granted_at, u.name as owner_name, u.email as owner_email FROM document_permissions dp JOIN documents d ON dp.document_id = d.id JOIN users u ON d.owner_id = u.id WHERE dp.user_id = ? AND dp.status = 'ACTIVE' ORDER BY dp.granted_at DESC").all(req.user.id);
    res.json({ documents });
  } catch (err) { next(err); }
});

app.get('/api/viewer/activity', requireAuth, (req, res, next) => {
  try {
    const db = getDatabase();
    const activity = db.prepare("SELECT a.id, a.action, a.result, a.timestamp, d.name as document_name FROM audit_logs a LEFT JOIN documents d ON a.document_id = d.id WHERE a.user_id = ? ORDER BY a.timestamp DESC LIMIT 50").all(req.user.id);
    res.json({ activity });
  } catch (err) { next(err); }
});

// DOCUMENT & PERMISSION ROUTES
app.post('/api/documents', requireAuth, upload.single('file'), (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No document file uploaded.' });

    const { name, description, category } = req.body;
    const documentName = (name && name.trim()) || req.file.originalname;
    const documentCategory = (category && category.trim()) || 'General';
    const storageKey = saveFile(req.file.buffer, req.file.originalname);
    const docId = uuidv4();
    const fileType = path.extname(req.file.originalname).toLowerCase().replace('.', '') || 'bin';
    const fileSize = req.file.size;
    const ownerId = req.user.id;

    const db = getDatabase();
    db.prepare("INSERT INTO documents (id, owner_id, name, description, category, file_type, file_size, storage_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(docId, ownerId, documentName, description || '', documentCategory, fileType, fileSize, storageKey);

    logEvent(db, { userId: ownerId, documentId: docId, action: 'DOCUMENT_UPLOAD', result: 'SUCCESS', ipAddress: req.ip, metadata: { name: documentName, category: documentCategory, fileType, fileSize } });
    res.status(201).json({ message: 'Document uploaded successfully.', document: { id: docId, name: documentName, category: documentCategory, fileType, fileSize } });
  } catch (err) { next(err); }
});

app.get('/api/documents', requireAuth, (req, res, next) => {
  try {
    const { search, category, fileType } = req.query;
    const userId = req.user.id;
    const userRole = req.user.role;
    const db = getDatabase();

    let query = '';
    const params = [];

    if (userRole === 'ADMIN') {
      query = "SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, d.updated_at, u.name as owner_name, u.email as owner_email, 'OWNER' as access_level FROM documents d JOIN users u ON d.owner_id = u.id WHERE 1=1";
      if (search) { query += ' AND (LOWER(d.name) LIKE ? OR LOWER(d.description) LIKE ?)'; params.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`); }
      if (category) { query += ' AND d.category = ?'; params.push(category); }
      if (fileType) { query += ' AND d.file_type = ?'; params.push(fileType.toLowerCase()); }
    } else {
      query = "SELECT DISTINCT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, d.updated_at, u.name as owner_name, u.email as owner_email, CASE WHEN d.owner_id = ? THEN 'OWNER' ELSE dp.permission_type END as access_level FROM documents d JOIN users u ON d.owner_id = u.id LEFT JOIN document_permissions dp ON d.id = dp.document_id AND dp.user_id = ? AND dp.status = 'ACTIVE' WHERE (d.owner_id = ? OR (dp.user_id = ? AND dp.status = 'ACTIVE'))";
      params.push(userId, userId, userId, userId);
      if (search) { query += ' AND (LOWER(d.name) LIKE ? OR LOWER(d.description) LIKE ?)'; params.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`); }
      if (category) { query += ' AND d.category = ?'; params.push(category); }
      if (fileType) { query += ' AND d.file_type = ?'; params.push(fileType.toLowerCase()); }
    }

    query += ' ORDER BY d.created_at DESC';
    res.json({ documents: db.prepare(query).all(...params) });
  } catch (err) { next(err); }
});

app.get('/api/documents/:id', requireAuth, requireDocumentPermission('READ'), (req, res, next) => {
  try {
    const db = getDatabase();
    logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'DOCUMENT_VIEW', result: 'SUCCESS', ipAddress: req.ip, metadata: { accessLevel: req.accessLevel } });
    res.json({ document: req.document, accessLevel: req.accessLevel });
  } catch (err) { next(err); }
});

app.get('/api/documents/:id/download', requireAuth, requireDocumentPermission('READ'), (req, res, next) => {
  try {
    const filePath = getFilePath(req.document.storage_key);
    if (!filePath) return res.status(404).json({ error: 'Storage file not found on server.' });

    const db = getDatabase();
    logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'DOCUMENT_DOWNLOAD', result: 'SUCCESS', ipAddress: req.ip, metadata: { accessLevel: req.accessLevel, name: req.document.name } });
    res.download(filePath, req.document.name);
  } catch (err) { next(err); }
});

app.patch('/api/documents/:id', requireAuth, requireDocumentPermission('EDIT'), (req, res, next) => {
  try {
    const { name, description, category } = req.body;
    const db = getDatabase();

    const newName = (name && name.trim()) || req.document.name;
    const newDesc = description !== undefined ? description : req.document.description;
    const newCat = (category && category.trim()) || req.document.category;

    db.prepare('UPDATE documents SET name = ?, description = ?, category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(newName, newDesc, newCat, req.document.id);
    logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'DOCUMENT_EDIT', result: 'SUCCESS', ipAddress: req.ip, metadata: { oldName: req.document.name, newName } });
    res.json({ message: 'Document updated successfully.' });
  } catch (err) { next(err); }
});

app.delete('/api/documents/:id', requireAuth, requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const db = getDatabase();
    deleteFile(req.document.storage_key);
    db.prepare('DELETE FROM documents WHERE id = ?').run(req.document.id);

    logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'DOCUMENT_DELETE', result: 'SUCCESS', ipAddress: req.ip, metadata: { documentName: req.document.name } });
    res.json({ message: 'Document deleted successfully.' });
  } catch (err) { next(err); }
});

app.get('/api/documents/:id/permissions', requireAuth, requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const db = getDatabase();
    const permissions = db.prepare("SELECT dp.id, dp.document_id, dp.user_id, dp.permission_type, dp.granted_at, dp.revoked_at, dp.status, u.name as user_name, u.email as user_email FROM document_permissions dp JOIN users u ON dp.user_id = u.id WHERE dp.document_id = ? ORDER BY dp.granted_at DESC").all(req.document.id);
    res.json({ permissions });
  } catch (err) { next(err); }
});

app.post('/api/documents/:id/permissions', requireAuth, requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const { userEmail, permissionType } = req.body;
    if (!userEmail || !userEmail.includes('@')) return res.status(400).json({ error: 'Valid recipient email address is required.' });
    if (!['READ', 'EDIT'].includes(permissionType)) return res.status(400).json({ error: "Permission type must be 'READ' or 'EDIT'." });

    const db = getDatabase();
    const targetUser = db.prepare('SELECT id, name, email FROM users WHERE LOWER(email) = ?').get(userEmail.trim().toLowerCase());
    if (!targetUser) return res.status(404).json({ error: 'No user registered with this email address.' });
    if (targetUser.id === req.user.id) return res.status(400).json({ error: 'You are the owner of this document and already have full control.' });

    const existingPerm = db.prepare('SELECT id, status FROM document_permissions WHERE document_id = ? AND user_id = ?').get(req.document.id, targetUser.id);

    if (existingPerm) {
      db.prepare("UPDATE document_permissions SET permission_type = ?, status = 'ACTIVE', revoked_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(permissionType, existingPerm.id);
      logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'PERMISSION_GRANTED', result: 'SUCCESS', ipAddress: req.ip, metadata: { recipientId: targetUser.id, permissionType } });
      return res.json({ message: `Updated permission to ${permissionType} for ${targetUser.email}.` });
    }

    const permId = uuidv4();
    db.prepare("INSERT INTO document_permissions (id, document_id, user_id, permission_type, granted_by, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')").run(permId, req.document.id, targetUser.id, permissionType, req.user.id);
    logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'PERMISSION_GRANTED', result: 'SUCCESS', ipAddress: req.ip, metadata: { recipientId: targetUser.id, permissionType } });

    res.status(201).json({ message: `Granted ${permissionType} permission to ${targetUser.email}.`, permissionId: permId });
  } catch (err) { next(err); }
});

app.patch('/api/documents/:id/permissions/:permissionId', requireAuth, requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const { permissionType } = req.body;
    const { permissionId } = req.params;
    if (!['READ', 'EDIT'].includes(permissionType)) return res.status(400).json({ error: "Permission type must be 'READ' or 'EDIT'." });

    const db = getDatabase();
    db.prepare("UPDATE document_permissions SET permission_type = ?, status = 'ACTIVE', revoked_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(permissionType, permissionId);
    logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'PERMISSION_CHANGED', result: 'SUCCESS', ipAddress: req.ip, metadata: { permissionId, newType: permissionType } });

    res.json({ message: `Permission updated to ${permissionType}.` });
  } catch (err) { next(err); }
});

app.delete('/api/documents/:id/permissions/:permissionId', requireAuth, requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const { permissionId } = req.params;
    const db = getDatabase();
    const perm = db.prepare('SELECT * FROM document_permissions WHERE id = ? AND document_id = ?').get(permissionId, req.document.id);
    if (!perm) return res.status(404).json({ error: 'Permission entry not found.' });

    const now = new Date().toISOString();
    db.prepare("UPDATE document_permissions SET status = 'REVOKED', revoked_at = ?, updated_at = ? WHERE id = ?").run(now, now, permissionId);
    logEvent(db, { userId: req.user.id, documentId: req.document.id, action: 'PERMISSION_REVOKED', result: 'SUCCESS', ipAddress: req.ip, metadata: { permissionId, targetUserId: perm.user_id } });

    res.json({ message: 'Permission revoked immediately.' });
  } catch (err) { next(err); }
});

// AUDIT ROUTES
app.get('/api/audit-logs', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const { userId, action, result, startDate, endDate } = req.query;
    const db = getDatabase();

    let query = "SELECT a.id, a.user_id, a.document_id, a.action, a.result, a.ip_address, a.metadata, a.timestamp, a.previous_hash, a.event_hash, u.name as user_name, u.email as user_email, d.name as document_name FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id LEFT JOIN documents d ON a.document_id = d.id WHERE 1=1";
    const params = [];

    if (userId) { query += ' AND a.user_id = ?'; params.push(userId); }
    if (action) { query += ' AND a.action = ?'; params.push(action); }
    if (result) { query += ' AND a.result = ?'; params.push(result); }
    if (startDate) { query += ' AND a.timestamp >= ?'; params.push(startDate); }
    if (endDate) { query += ' AND a.timestamp <= ?'; params.push(endDate); }

    query += ' ORDER BY a.timestamp DESC LIMIT 200';
    res.json({ logs: db.prepare(query).all(...params) });
  } catch (err) { next(err); }
});

app.get('/api/audit-logs/verify', requireAuth, requireRole('ADMIN'), (req, res, next) => {
  try {
    const db = getDatabase();
    res.json(verifyAuditChain(db));
  } catch (err) { next(err); }
});

// PAGE FALLBACKS
function serveFile(res, filename) {
  const primaryPath = path.join(__dirname, 'public', filename);
  if (fs.existsSync(primaryPath)) return res.sendFile(primaryPath);

  const rootPath = path.join(__dirname, filename);
  if (fs.existsSync(rootPath)) return res.sendFile(rootPath);

  res.sendFile(path.join(__dirname, filename));
}

app.get('/login', (req, res) => serveFile(res, 'index.html'));
app.get('/register', (req, res) => serveFile(res, 'register.html'));
app.get('/admin-dashboard', (req, res) => serveFile(res, 'admin-dashboard.html'));
app.get('/owner-dashboard', (req, res) => serveFile(res, 'owner-dashboard.html'));
app.get('/viewer-dashboard', (req, res) => serveFile(res, 'viewer-dashboard.html'));

// GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
  console.error('[TrustVault Error Handler]:', err);
  const db = getDatabase();
  logEvent(db, {
    userId: req.user ? req.user.id : null,
    action: 'SYSTEM_ERROR',
    result: 'FAILURE',
    ipAddress: req.ip || req.connection ? req.connection.remoteAddress : '',
    metadata: { errorMessage: err.message, path: req.originalUrl }
  });

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'File size exceeds maximum allowed limit (15MB).' });
  }

  res.status(err.status || 500).json({ error: err.message || 'An internal server error occurred.' });
});

// ============================================================================
// 6. INITIAL SEED & SERVER START
// ============================================================================
function seedDefaultAdmin() {
  const db = getDatabase();
  const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN'").get().count;

  if (adminCount === 0) {
    const adminId = uuidv4();
    const adminEmail = 'admin@trustvault.com';
    const adminPassword = 'AdminPassword123!';
    const passwordHash = bcrypt.hashSync(adminPassword, 10);

    db.prepare("INSERT INTO users (id, name, email, password_hash, role, status) VALUES (?, 'System Administrator', ?, ?, 'ADMIN', 'ACTIVE')")
      .run(adminId, adminEmail, passwordHash);

    logEvent(db, {
      userId: adminId, action: 'SYSTEM_ADMIN_INITIALIZED', result: 'SUCCESS', metadata: { email: adminEmail, initialRole: 'ADMIN' }
    });

    console.log('=====================================================');
    console.log('[TrustVault Seed]: Default Administrator created.');
    console.log('Email: admin@trustvault.com');
    console.log('Password: AdminPassword123!');
    console.log('=====================================================');
  }
}

// Synchronous seed call on startup
seedDefaultAdmin();

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[TrustVault Server] Running on port ${PORT} (${process.env.NODE_ENV || 'development'})`);
  });
}

module.exports = app;
