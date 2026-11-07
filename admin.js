const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { logEvent } = require('../services/auditService');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/roles');

router.use(requireAuth);
router.use(requireRole('ADMIN'));

/**
 * GET /api/admin/dashboard
 * Returns system-wide metrics and chart datasets.
 */
router.get('/dashboard', (req, res, next) => {
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

    // Role breakdown
    const rolesCount = db.prepare(`
      SELECT role, COUNT(*) as count FROM users GROUP BY role
    `).all();

    // Recent activity
    const recentActivity = db.prepare(`
      SELECT a.id, a.action, a.result, a.timestamp, a.ip_address,
             u.name as user_name, u.email as user_email,
             d.name as document_name
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN documents d ON a.document_id = d.id
      ORDER BY a.timestamp DESC
      LIMIT 10
    `).all();

    // Recent uploads
    const recentUploads = db.prepare(`
      SELECT d.id, d.name, d.category, d.file_type, d.file_size, d.created_at, u.name as owner_name
      FROM documents d
      JOIN users u ON d.owner_id = u.id
      ORDER BY d.created_at DESC
      LIMIT 5
    `).all();

    res.json({
      stats: {
        totalUsers,
        activeUsers,
        disabledUsers,
        totalDocs,
        totalStorageBytes,
        totalSharedDocs,
        totalPermissions,
        securityEventsCount
      },
      rolesBreakdown: rolesCount,
      recentActivity,
      recentUploads
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/admin/users
 */
router.get('/users', (req, res, next) => {
  try {
    const { search, role, status } = req.query;
    const db = getDatabase();

    let query = 'SELECT id, name, email, role, status, created_at, last_login_at FROM users WHERE 1=1';
    const params = [];

    if (search) {
      query += ' AND (LOWER(name) LIKE ? OR LOWER(email) LIKE ?)';
      params.push(`%${search.toLowerCase()}%`, `%${search.toLowerCase()}%`);
    }

    if (role) {
      query += ' AND role = ?';
      params.push(role);
    }

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    query += ' ORDER BY created_at DESC';

    const users = db.prepare(query).all(...params);
    res.json({ users });
  } catch (err) {
    next(err);
  }
});

/**
 * PATCH /api/admin/users/:id/role
 */
router.patch('/users/:id/role', (req, res, next) => {
  try {
    const { role } = req.body;
    const targetUserId = req.params.id;

    if (!['ADMIN', 'OWNER', 'VIEWER'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified.' });
    }

    const db = getDatabase();
    const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(targetUserId);

    if (!targetUser) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Protect last active administrator from losing ADMIN role
    if (targetUser.role === 'ADMIN' && role !== 'ADMIN') {
      const adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'").get().count;
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'Cannot demote the last remaining active Administrator.' });
      }
    }

    db.prepare("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(role, targetUserId);

    logEvent(db, {
      userId: req.user.id,
      action: 'ADMIN_ROLE_CHANGE',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { targetUserId, targetUserEmail: targetUser.email, oldRole: targetUser.role, newRole: role }
    });

    res.json({ message: `Role updated to ${role} successfully.` });
  } catch (err) {
    next(err);
  }
});

/**
 * PATCH /api/admin/users/:id/status
 */
router.patch('/users/:id/status', (req, res, next) => {
  try {
    const { status } = req.body;
    const targetUserId = req.params.id;

    if (!['ACTIVE', 'DISABLED'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status specified.' });
    }

    const db = getDatabase();
    const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(targetUserId);

    if (!targetUser) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Protect last admin from being disabled
    if (targetUser.role === 'ADMIN' && status === 'DISABLED') {
      const activeAdminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'").get().count;
      if (activeAdminCount <= 1) {
        return res.status(400).json({ error: 'Cannot disable the last remaining active Administrator.' });
      }
    }

    db.prepare("UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(status, targetUserId);

    logEvent(db, {
      userId: req.user.id,
      action: 'ADMIN_STATUS_CHANGE',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { targetUserId, targetUserEmail: targetUser.email, oldStatus: targetUser.status, newStatus: status }
    });

    res.json({ message: `User status updated to ${status} successfully.` });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/admin/documents
 */
router.get('/documents', (req, res, next) => {
  try {
    const db = getDatabase();
    const documents = db.prepare(`
      SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at,
             u.id as owner_id, u.name as owner_name, u.email as owner_email,
             (SELECT COUNT(*) FROM document_permissions dp WHERE dp.document_id = d.id AND dp.status = 'ACTIVE') as active_shares_count
      FROM documents d
      JOIN users u ON d.owner_id = u.id
      ORDER BY d.created_at DESC
    `).all();

    res.json({ documents });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/admin/security-events
 */
router.get('/security-events', (req, res, next) => {
  try {
    const db = getDatabase();
    const events = db.prepare(`
      SELECT a.id, a.user_id, a.action, a.result, a.ip_address, a.metadata, a.timestamp,
             u.name as user_name, u.email as user_email
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE a.result = 'FAILURE' OR a.action LIKE 'UNAUTHORIZED%' OR a.action LIKE 'DISABLED%' OR a.action LIKE 'ADMIN%'
      ORDER BY a.timestamp DESC
      LIMIT 100
    `).all();

    res.json({ events });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
