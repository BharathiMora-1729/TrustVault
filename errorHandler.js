const { logEvent } = require('../services/auditService');
const { getDatabase } = require('../config/database');

/**
 * Global Express error handling middleware.
 */
function errorHandler(err, req, res, next) {
  console.error('[TrustVault Error Handler]:', err);

  const db = getDatabase();
  logEvent(db, {
    userId: req.user ? req.user.id : null,
    action: 'SYSTEM_ERROR',
    result: 'FAILURE',
    ipAddress: req.ip || req.connection ? req.connection.remoteAddress : '',
    metadata: {
      errorMessage: err.message,
      path: req.originalUrl
    }
  });

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'File size exceeds maximum allowed limit (15MB).' });
  }

  res.status(err.status || 500).json({
    error: err.message || 'An internal server error occurred.'
  });
}

module.exports = errorHandler;
