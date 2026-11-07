const { getDatabase } = require('../config/database');
const { logEvent } = require('../services/auditService');

/**
 * Middleware restricting access to specified roles.
 * @param {...string} allowedRoles
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      const db = getDatabase();
      logEvent(db, {
        userId: req.user.id,
        action: 'UNAUTHORIZED_ROLE_ACCESS_ATTEMPT',
        result: 'FAILURE',
        ipAddress: req.ip || req.connection.remoteAddress,
        metadata: {
          userRole: req.user.role,
          requiredRoles: allowedRoles,
          path: req.originalUrl
        }
      });

      return res.status(403).json({
        error: `Forbidden: Access restricted to [${allowedRoles.join(', ')}] roles.`
      });
    }

    next();
  };
}

module.exports = {
  requireRole
};
