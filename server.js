require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const { getDatabase } = require('./config/database');
const { logEvent } = require('./services/auditService');
const errorHandler = require('./middleware/errorHandler');

// Import routes
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const ownerRoutes = require('./routes/owner');
const viewerRoutes = require('./routes/viewer');
const documentRoutes = require('./routes/documents');
const permissionRoutes = require('./routes/permissions');
const auditRoutes = require('./routes/audit');

const app = express();

// Security Headers
app.use(helmet({
  contentSecurityPolicy: false // Allows Bootstrap CDN & Chart.js scripts
}));

// CORS
app.use(cors());

// Rate Limiter for general API routes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this IP, please try again after 15 minutes.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many authentication attempts, please try again later.' }
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
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// Mount API routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/owner', ownerRoutes);
app.use('/api/viewer', viewerRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/documents', permissionRoutes);
app.use('/api/audit-logs', auditRoutes);

// Single Page Application Fallback for static HTML pages
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public/register.html')));
app.get('/admin-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/admin-dashboard.html')));
app.get('/owner-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/owner-dashboard.html')));
app.get('/viewer-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public/viewer-dashboard.html')));

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

// Initialize database & start server if run directly
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
