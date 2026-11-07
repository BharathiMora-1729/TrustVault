const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

/**
 * GET /api/viewer/dashboard
 */
router.get('/dashboard', (req, res, next) => {
  try {
    const db = getDatabase();
    const userId = req.user.id;

    const totalSharedDocs = db.prepare(`
      SELECT COUNT(*) as count
      FROM document_permissions dp
      WHERE dp.user_id = ? AND dp.status = 'ACTIVE'
    `).get(userId).count;

    const readOnlyDocs = db.prepare(`
      SELECT COUNT(*) as count
      FROM document_permissions dp
      WHERE dp.user_id = ? AND dp.status = 'ACTIVE' AND dp.permission_type = 'READ'
    `).get(userId).count;

    const editableDocs = db.prepare(`
      SELECT COUNT(*) as count
      FROM document_permissions dp
      WHERE dp.user_id = ? AND dp.status = 'ACTIVE' AND dp.permission_type = 'EDIT'
    `).get(userId).count;

    const sharedDocuments = db.prepare(`
      SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at,
             dp.permission_type, dp.granted_at,
             u.name as owner_name, u.email as owner_email
      FROM document_permissions dp
      JOIN documents d ON dp.document_id = d.id
      JOIN users u ON d.owner_id = u.id
      WHERE dp.user_id = ? AND dp.status = 'ACTIVE'
      ORDER BY dp.granted_at DESC
    `).all(userId);

    res.json({
      stats: {
        totalSharedDocs,
        readOnlyDocs,
        editableDocs
      },
      sharedDocuments
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/viewer/documents
 */
router.get('/documents', (req, res, next) => {
  try {
    const db = getDatabase();
    const userId = req.user.id;

    const documents = db.prepare(`
      SELECT d.id, d.name, d.description, d.category, d.file_type, d.file_size, d.created_at,
             dp.permission_type, dp.granted_at,
             u.name as owner_name, u.email as owner_email
      FROM document_permissions dp
      JOIN documents d ON dp.document_id = d.id
      JOIN users u ON d.owner_id = u.id
      WHERE dp.user_id = ? AND dp.status = 'ACTIVE'
      ORDER BY dp.granted_at DESC
    `).all(userId);

    res.json({ documents });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/viewer/activity
 */
router.get('/activity', (req, res, next) => {
  try {
    const db = getDatabase();
    const userId = req.user.id;

    const activity = db.prepare(`
      SELECT a.id, a.action, a.result, a.timestamp,
             d.name as document_name
      FROM audit_logs a
      LEFT JOIN documents d ON a.document_id = d.id
      WHERE a.user_id = ?
      ORDER BY a.timestamp DESC
      LIMIT 50
    `).all(userId);

    res.json({ activity });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
