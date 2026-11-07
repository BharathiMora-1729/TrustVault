const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { logEvent } = require('../services/auditService');
const { requireAuth } = require('../middleware/auth');

/**
 * POST /api/auth/register
 * Normal registration without invitation codes/links/fields.
 */
router.post('/register', async (req, res, next) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Full Name is required.' });
    }

    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'A valid Email Address is required.' });
    }

    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Password and Confirm Password do not match.' });
    }

    const db = getDatabase();
    const normalizedEmail = email.trim().toLowerCase();

    // Check for existing user
    const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = ?').get(normalizedEmail);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email address already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const userId = uuidv4();

    // Default role is OWNER, status is ACTIVE. Self-promotion to ADMIN is prohibited.
    const stmt = db.prepare(`
      INSERT INTO users (id, name, email, password_hash, role, status)
      VALUES (?, ?, ?, ?, 'OWNER', 'ACTIVE')
    `);

    stmt.run(userId, name.trim(), normalizedEmail, passwordHash);

    logEvent(db, {
      userId,
      action: 'USER_REGISTER',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { name: name.trim(), email: normalizedEmail, assignedRole: 'OWNER' }
    });

    res.status(201).json({
      message: 'Registration successful! You can now log in.',
      userId
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/login
 */
router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const db = getDatabase();
    const normalizedEmail = email.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(normalizedEmail);

    if (!user) {
      logEvent(db, {
        action: 'USER_LOGIN_FAILED',
        result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress,
        metadata: { email: normalizedEmail, reason: 'Invalid email' }
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      logEvent(db, {
        userId: user.id,
        action: 'USER_LOGIN_FAILED',
        result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress,
        metadata: { email: normalizedEmail, reason: 'Incorrect password' }
      });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.status === 'DISABLED') {
      logEvent(db, {
        userId: user.id,
        action: 'DISABLED_ACCOUNT_LOGIN_ATTEMPT',
        result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress,
        metadata: { email: normalizedEmail }
      });
      return res.status(403).json({ error: 'Your account has been disabled. Please contact an administrator.' });
    }

    // Regenerate session for security
    req.session.regenerate((err) => {
      if (err) return next(err);

      req.session.userId = user.id;

      // Update last login timestamp
      const now = new Date().toISOString();
      db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now, user.id);

      logEvent(db, {
        userId: user.id,
        action: 'USER_LOGIN_SUCCESS',
        result: 'SUCCESS',
        ipAddress: req.ip || req.connection.remoteAddress,
        metadata: { email: normalizedEmail, role: user.role }
      });

      res.json({
        message: 'Login successful.',
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status
        }
      });
    });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', requireAuth, (req, res, next) => {
  const db = getDatabase();
  const userId = req.user.id;

  logEvent(db, {
    userId,
    action: 'USER_LOGOUT',
    result: 'SUCCESS',
    ipAddress: req.ip || req.connection.remoteAddress
  });

  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully.' });
  });
});

/**
 * GET /api/auth/me
 */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
