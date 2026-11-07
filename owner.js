const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/roles');

router.use(requireAuth);
router.use(requireRole('OWNER', 'ADMIN'));

/**
 * GET /api/owner/dashboard
 */
router.get('/dashboard', (req, res, next) => {
  try {
    const db = getDatabase();
    const ownerId = req.user.id;

    const myTotalDocs = db.prepare('SELECT COUNT(*) as count FROM documents WHERE owner_id = ?').get(ownerId).count;
    const storageUsedBytes = db.prepare('SELECT SUM(file_size) as total FROM documents WHERE owner_id = ?').get(ownerId).total || 0;

    const totalSharedWithOthers = db.prepare(`
      SELECT COUNT(DISTINCT dp.document_id) as count
      FROM document_permissions dp
      JOIN documents d ON dp.document_id = d.id
      WHERE d.owner_id = ? AND dp.status = 'ACTIVE'
    `).get(ownerId).count;

    const activePermissionsCount = db.prepare(`
      SELECT COUNT(*) as count
      FROM document_permissions dp
      JOIN documents d ON dp.document_id = d.id
      WHERE d.owner_id = ? AND dp.status = 'ACTIVE'
    `).get(ownerId).count;

    const recentDocs = db.prepare(`
      SELECT d.id, d.name, d.category, d.file_type, d.file_size, d.created_at,
             (SELECT COUNT(*) FROM document_permissions dp WHERE dp.document_id = d.id AND dp.status = 'ACTIVE') as shared_count
      FROM documents d
      WHERE d.owner_id = ?
      ORDER BY d.created_at DESC
      LIMIT 5
    `).all(ownerId);

    const recentShares = db.prepare(`
      SELECT dp.id, dp.permission_type, dp.granted_at, dp.status,
             d.name as document_name,
             u.name as target_user_name, u.email as target_user_email
      FROM document_permissions dp
      JOIN documents d ON dp.document_id = d.id
      JOIN users u ON dp.user_id = u.id
      WHERE d.owner_id = ?
      ORDER BY dp.granted_at DESC
      LIMIT 5
    `).all(ownerId);

    res.json({
      stats: {
        myTotalDocs,
        storageUsedBytes,
        totalSharedWithOthers,
        activePermissionsCount
      },
      recentDocs,
      recentShares
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/owner/documents
 */
router.get('/documents', (req, res, next) => {
  try {
    const db = getDatabase();
    const ownerId = req.user.id;

    const documents = db.prepare(`
      SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at, d.updated_at,
             (SELECT COUNT(*) FROM document_permissions dp WHERE dp.document_id = d.id AND dp.status = 'ACTIVE') as shared_count
      FROM documents d
      WHERE d.owner_id = ?
      ORDER BY d.created_at DESC
    `).all(ownerId);

    res.json({ documents });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/owner/permissions
 */
router.get('/permissions', (req, res, next) => {
  try {
    const db = getDatabase();
    const ownerId = req.user.id;

    const permissions = db.prepare(`
      SELECT dp.id, dp.document_id, dp.user_id, dp.permission_type, dp.granted_at, dp.revoked_at, dp.status,
             d.name as document_name,
             u.name as user_name, u.email as user_email
      FROM document_permissions dp
      JOIN documents d ON dp.document_id = d.id
      JOIN users u ON dp.user_id = u.id
      WHERE d.owner_id = ?
      ORDER BY dp.granted_at DESC
    `).all(ownerId);

    res.json({ permissions });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/owner/activity
 */
router.get('/activity', (req, res, next) => {
  try {
    const db = getDatabase();
    const ownerId = req.user.id;

    const activity = db.prepare(`
      SELECT a.id, a.action, a.result, a.timestamp, a.metadata,
             d.name as document_name
      FROM audit_logs a
      LEFT JOIN documents d ON a.document_id = d.id
      WHERE a.user_id = ? OR d.owner_id = ?
      ORDER BY a.timestamp DESC
      LIMIT 50
    `).all(ownerId, ownerId);

    res.json({ activity });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
