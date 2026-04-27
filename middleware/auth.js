const jwt = require('jsonwebtoken');
const { run } = require('../db/database');
const { audit } = require('../services/auditService');

function extractBearer(req) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}

function requireAuth(req, res, next) {
  const token = extractBearer(req);
  if (!token) return res.status(401).json({ error: 'Missing access token', code: 'AUTH_REQUIRED' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'development-jwt-secret-change-me');
    if (!payload.userId || !payload.sessionId) throw new Error('Invalid payload');
    const session = run((db) => db.prepare('SELECT id, user_id, is_revoked, expires_at FROM sessions WHERE id = ?').get(payload.sessionId), null);
    const now = Math.floor(Date.now() / 1000);
    if (!session || session.user_id !== payload.userId || session.is_revoked || session.expires_at <= now) throw new Error('Invalid session');
    req.user = { userId: payload.userId, sessionId: payload.sessionId };
    return next();
  } catch (error) {
    audit({ eventType: 'INVALID_TOKEN_ATTEMPT', req, metadata: { reason: error.message } });
    return res.status(401).json({ error: 'Invalid or expired token', code: 'INVALID_TOKEN' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    const user = run((db) => db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.userId), null);
    if (!user || user.role !== 'admin') {
      audit({ userId: req.user.userId, eventType: 'PRIVILEGE_ESCALATION_ATTEMPT', req, metadata: { path: req.originalUrl } });
      return res.status(403).json({ error: 'Admin privileges required', code: 'ADMIN_REQUIRED' });
    }
    return next();
  });
}

module.exports = { requireAuth, requireAdmin };
