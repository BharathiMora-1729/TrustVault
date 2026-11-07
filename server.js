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

/**
 * Universal safe module resolver.
 * Handles both structured folder uploads (e.g. ./config/database)
 * AND flat root uploads (e.g. ./database) on GitHub/Render.
 */
function safeRequire(primaryPath, fallbackPath) {
  try {
    return require(primaryPath);
  } catch (err) {
    if (err.code === 'MODULE_NOT_FOUND' && fallbackPath) {
      try {
        return require(fallbackPath);
      } catch (fallbackErr) {
        throw err;
      }
    }
    throw err;
  }
}

// Load Modules with Fallbacks
const { getDatabase } = safeRequire('./config/database', './database');
const { logEvent } = safeRequire('./services/auditService', './auditService');
const errorHandler = safeRequire('./middleware/errorHandler', './errorHandler');

const authRoutes = safeRequire('./routes/auth', './auth');
const adminRoutes = safeRequire('./routes/admin', './admin');
const ownerRoutes = safeRequire('./routes/owner', './owner');
const viewerRoutes = safeRequire('./routes/viewer', './viewer');
const documentRoutes = safeRequire('./routes/documents', './documents');
const permissionRoutes = safeRequire('./routes/permissions', './permissions');
const auditRoutes = safeRequire('./routes/audit', './audit');

const app = express();

// Security Headers
app.use(helmet({
  contentSecurityPolicy: false
}));

// CORS
app.use(cors());

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many login attempts, please try again later.' }
});

app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session handling
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

// Serve static frontend files (Checks both public/ and root directory)
const publicDir = fs.existsSync(path.join(__dirname, 'public')) ? path.join(__dirname, 'public') : __dirname;
app.use(express.static(publicDir));

// Mount API routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/owner', ownerRoutes);
app.use('/api/viewer', viewerRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/documents', permissionRoutes);
app.use('/api/audit-logs', auditRoutes);

// Page Fallbacks
function serveFile(res, primaryFile, fallbackFile) {
  const primaryPath = path.join(__dirname, 'public', primaryFile);
  if (fs.existsSync(primaryPath)) {
    return res.sendFile(primaryPath);
  }
  const rootPath = path.join(__dirname, fallbackFile);
  if (fs.existsSync(rootPath)) {
    return res.sendFile(rootPath);
  }
  res.sendFile(path.join(__dirname, primaryFile));
}

app.get('/login', (req, res) => serveFile(res, 'index.html', 'index.html'));
app.get('/register', (req, res) => serveFile(res, 'register.html', 'register.html'));
app.get('/admin-dashboard', (req, res) => serveFile(res, 'admin-dashboard.html', 'admin-dashboard.html'));
app.get('/owner-dashboard', (req, res) => serveFile(res, 'owner-dashboard.html', 'owner-dashboard.html'));
app.get('/viewer-dashboard', (req, res) => serveFile(res, 'viewer-dashboard.html', 'viewer-dashboard.html'));

// Global Error Handler
app.use(errorHandler);

/**
 * Seed initial Administrator account if no admin exists in DB.
 */
async function seedDefaultAdmin() {
  const db = getDatabase();
  const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN'").get().count;

  if (adminCount === 0) {
    const adminId = uuidv4();
    const adminEmail = 'admin@trustvault.com';
    const adminPassword = 'AdminPassword123!';
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(adminPassword, salt);

    db.prepare(`
      INSERT INTO users (id, name, email, password_hash, role, status)
      VALUES (?, 'System Administrator', ?, ?, 'ADMIN', 'ACTIVE')
    `).run(adminId, adminEmail, passwordHash);

    logEvent(db, {
      userId: adminId,
      action: 'SYSTEM_ADMIN_INITIALIZED',
      result: 'SUCCESS',
      metadata: { email: adminEmail, initialRole: 'ADMIN' }
    });

    console.log('=====================================================');
    console.log('[TrustVault Seed]: Default Administrator created.');
    console.log('Email: admin@trustvault.com');
    console.log('Password: AdminPassword123!');
    console.log('=====================================================');
  }
}

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  seedDefaultAdmin().then(() => {
    app.listen(PORT, () => {
      console.log(`[TrustVault Server] Running on port ${PORT} (${process.env.NODE_ENV || 'development'})`);
    });
  }).catch(err => {
    console.error('Failed to seed default admin:', err);
  });
}

module.exports = app;
