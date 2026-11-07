const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { verifyAuditChain } = require('../services/auditService');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/roles');

router.use(requireAuth);
router.use(requireRole('ADMIN'));

/**
 * GET /api/audit-logs
 * Filtering by user, action, result, date range.
 */
router.get('/', (req, res, next) => {
  try {
    const { userId, action, result, startDate, endDate } = req.query;
    const db = getDatabase();

    let query = `
      SELECT a.id, a.user_id, a.document_id, a.action, a.result, a.ip_address, a.metadata, a.timestamp, a.previous_hash, a.event_hash,
             u.name as user_name, u.email as user_email,
             d.name as document_name
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN documents d ON a.document_id = d.id
      WHERE 1=1
    `;
    const params = [];

    if (userId) {
      query += ' AND a.user_id = ?';
      params.push(userId);
    }
    if (action) {
      query += ' AND a.action = ?';
      params.push(action);
    }
    if (result) {
      query += ' AND a.result = ?';
      params.push(result);
    }
    if (startDate) {
      query += ' AND a.timestamp >= ?';
      params.push(startDate);
    }
    if (endDate) {
      query += ' AND a.timestamp <= ?';
      params.push(endDate);
    }

    query += ' ORDER BY a.timestamp DESC LIMIT 200';

    const logs = db.prepare(query).all(...params);
    res.json({ logs });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/audit-logs/verify
 * Cryptographic audit hash chain verification.
 */
router.get('/verify', (req, res, next) => {
  try {
    const db = getDatabase();
    const verificationReport = verifyAuditChain(db);
    res.json(verificationReport);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
