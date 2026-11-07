const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { logEvent } = require('../services/auditService');
const { requireAuth } = require('../middleware/auth');
const { requireDocumentPermission } = require('../middleware/permissions');

router.use(requireAuth);

/**
 * GET /api/documents/:id/permissions
 */
router.get('/:id/permissions', requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const db = getDatabase();
    const permissions = db.prepare(`
      SELECT dp.id, dp.document_id, dp.user_id, dp.permission_type, dp.granted_at, dp.revoked_at, dp.status,
             u.name as user_name, u.email as user_email
      FROM document_permissions dp
      JOIN users u ON dp.user_id = u.id
      WHERE dp.document_id = ?
      ORDER BY dp.granted_at DESC
    `).all(req.document.id);

    res.json({ permissions });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/documents/:id/permissions
 * Grant permission to a registered user by email.
 */
router.post('/:id/permissions', requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const { userEmail, permissionType } = req.body;

    if (!userEmail || !userEmail.includes('@')) {
      return res.status(400).json({ error: 'Valid recipient email address is required.' });
    }

    if (!['READ', 'EDIT'].includes(permissionType)) {
      return res.status(400).json({ error: "Permission type must be 'READ' or 'EDIT'." });
    }

    const db = getDatabase();
    const targetUser = db.prepare('SELECT id, name, email FROM users WHERE LOWER(email) = ?').get(userEmail.trim().toLowerCase());

    if (!targetUser) {
      return res.status(404).json({ error: 'No user registered with this email address.' });
    }

    if (targetUser.id === req.user.id) {
      return res.status(400).json({ error: 'You are the owner of this document and already have full control.' });
    }

    // Check if permission already exists
    const existingPerm = db.prepare(`
      SELECT id, status FROM document_permissions WHERE document_id = ? AND user_id = ?
    `).get(req.document.id, targetUser.id);

    if (existingPerm) {
      db.prepare(`
        UPDATE document_permissions
        SET permission_type = ?, status = 'ACTIVE', revoked_at = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(permissionType, existingPerm.id);

      logEvent(db, {
        userId: req.user.id,
        documentId: req.document.id,
        action: 'PERMISSION_GRANTED',
        result: 'SUCCESS',
        ipAddress: req.ip || req.connection.remoteAddress,
        metadata: { recipientId: targetUser.id, recipientEmail: targetUser.email, permissionType }
      });

      return res.json({ message: `Updated permission to ${permissionType} for ${targetUser.email}.` });
    }

    const permId = uuidv4();
    db.prepare(`
      INSERT INTO document_permissions (id, document_id, user_id, permission_type, granted_by, status)
      VALUES (?, ?, ?, ?, ?, 'ACTIVE')
    `).run(permId, req.document.id, targetUser.id, permissionType, req.user.id);

    logEvent(db, {
      userId: req.user.id,
      documentId: req.document.id,
      action: 'PERMISSION_GRANTED',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { recipientId: targetUser.id, recipientEmail: targetUser.email, permissionType }
    });

    res.status(201).json({
      message: `Granted ${permissionType} permission to ${targetUser.email}.`,
      permissionId: permId
    });
  } catch (err) {
    next(err);
  }
});

/**
 * PATCH /api/documents/:id/permissions/:permissionId
 */
router.patch('/:id/permissions/:permissionId', requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const { permissionType } = req.body;
    const { permissionId } = req.params;

    if (!['READ', 'EDIT'].includes(permissionType)) {
      return res.status(400).json({ error: "Permission type must be 'READ' or 'EDIT'." });
    }

    const db = getDatabase();
    const perm = db.prepare('SELECT * FROM document_permissions WHERE id = ? AND document_id = ?').get(permissionId, req.document.id);

    if (!perm) {
      return res.status(404).json({ error: 'Permission entry not found.' });
    }

    db.prepare(`
      UPDATE document_permissions
      SET permission_type = ?, status = 'ACTIVE', revoked_at = NULL, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(permissionType, permissionId);

    logEvent(db, {
      userId: req.user.id,
      documentId: req.document.id,
      action: 'PERMISSION_CHANGED',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { permissionId, newType: permissionType }
    });

    res.json({ message: `Permission updated to ${permissionType}.` });
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/documents/:id/permissions/:permissionId
 * Immediate permission revocation.
 */
router.delete('/:id/permissions/:permissionId', requireDocumentPermission('OWNER'), (req, res, next) => {
  try {
    const { permissionId } = req.params;
    const db = getDatabase();

    const perm = db.prepare('SELECT * FROM document_permissions WHERE id = ? AND document_id = ?').get(permissionId, req.document.id);
    if (!perm) {
      return res.status(404).json({ error: 'Permission entry not found.' });
    }

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE document_permissions
      SET status = 'REVOKED', revoked_at = ?, updated_at = ?
      WHERE id = ?
    `).run(now, now, permissionId);

    logEvent(db, {
      userId: req.user.id,
      documentId: req.document.id,
      action: 'PERMISSION_REVOKED',
      result: 'SUCCESS',
      ipAddress: req.ip || req.connection.remoteAddress,
      metadata: { permissionId, targetUserId: perm.user_id }
    });

    res.json({ message: 'Permission revoked immediately.' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
