const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const GENESIS_HASH = '0'.repeat(64);

/**
 * Calculates HMAC-SHA256 signature for an audit log entry.
 * @param {object} payload
 * @param {string} secret
 * @returns {string} hex hash
 */
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

/**
 * Appends a tamper-evident audit event to database.
 * @param {Database.Database} db
 * @param {object} eventData
 * @returns {object} inserted log entry
 */
function logEvent(db, { userId = null, documentId = null, action, result = 'SUCCESS', ipAddress = '', metadata = {} }) {
  const auditSecret = process.env.TRUSTVAULT_AUDIT_SECRET || 'trustvault-default-audit-secret-key';

  // Find previous log entry hash
  const lastLog = db.prepare('SELECT event_hash FROM audit_logs ORDER BY rowid DESC LIMIT 1').get();
  const previousHash = lastLog ? lastLog.event_hash : GENESIS_HASH;

  const id = uuidv4();
  const timestamp = new Date().toISOString();
  const metadataStr = typeof metadata === 'string' ? metadata : JSON.stringify(metadata);

  const eventHash = calculateEventHash({
    id,
    userId,
    documentId,
    action,
    result,
    ipAddress,
    metadata: metadataStr,
    timestamp,
    previousHash
  }, auditSecret);

  const stmt = db.prepare(`
    INSERT INTO audit_logs (id, user_id, document_id, action, result, ip_address, metadata, timestamp, previous_hash, event_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(id, userId, documentId, action, result, ipAddress, metadataStr, timestamp, previousHash, eventHash);

  return {
    id,
    userId,
    documentId,
    action,
    result,
    ipAddress,
    metadata: metadataStr,
    timestamp,
    previousHash,
    eventHash
  };
}

/**
 * Verifies the integrity of the audit log chain.
 * @param {Database.Database} db
 * @returns {object} { valid: boolean, totalLogs: number, tamperedAt?: object }
 */
function verifyAuditChain(db) {
  const auditSecret = process.env.TRUSTVAULT_AUDIT_SECRET || 'trustvault-default-audit-secret-key';
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY rowid ASC').all();

  let expectedPreviousHash = GENESIS_HASH;

  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];

    // Verify previous hash chain connection
    if (log.previous_hash !== expectedPreviousHash) {
      return {
        valid: false,
        totalLogs: logs.length,
        tamperedAt: {
          id: log.id,
          index: i,
          reason: `Previous hash mismatch. Expected ${expectedPreviousHash}, found ${log.previous_hash}`
        }
      };
    }

    // Recompute current event hash
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
        tamperedAt: {
          id: log.id,
          index: i,
          reason: `Event hash mismatch. Recomputed ${recomputedHash}, found ${log.event_hash}`
        }
      };
    }

    expectedPreviousHash = log.event_hash;
  }

  return {
    valid: true,
    totalLogs: logs.length
  };
}

module.exports = {
  logEvent,
  verifyAuditChain,
  calculateEventHash
};
