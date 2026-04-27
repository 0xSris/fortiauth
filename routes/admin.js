const express = require('express');
const { run } = require('../db/database');
const { requireAdmin } = require('../middleware/auth');
const { validators } = require('../utils/validators');
const { rejectInvalid } = require('../middleware/sanitize');
const { audit } = require('../services/auditService');
const { adminSecurityStats } = require('../services/securityService');
const { getPolicy, updatePolicy } = require('../services/policyService');
const { askGroq } = require('../services/aiService');

const router = express.Router();
router.use(requireAdmin);

router.get('/users', validators.pagination, validators.search, rejectInvalid, (req, res) => {
  const page = req.query.page || 1;
  const limit = req.query.limit || 25;
  const offset = (page - 1) * limit;
  const search = `%${req.query.search || ''}%`;
  const users = run((db) => db.prepare('SELECT u.id, u.username, u.email, u.role, u.is_locked, u.failed_attempts, u.last_login, u.created_at, COALESCE(m.is_enabled, 0) AS mfa_enabled FROM users u LEFT JOIN mfa_configs m ON m.user_id = u.id WHERE u.username LIKE ? OR u.email LIKE ? ORDER BY u.created_at DESC LIMIT ? OFFSET ?').all(search, search, limit, offset), []);
  const total = run((db) => db.prepare('SELECT COUNT(*) AS count FROM users WHERE username LIKE ? OR email LIKE ?').get(search, search), { count: 0 });
  return res.json({ users, page, limit, total: total.count });
});

router.get('/users/:id', validators.userId, rejectInvalid, (req, res) => {
  const user = run((db) => db.prepare('SELECT u.id, u.username, u.email, u.role, u.is_locked, u.failed_attempts, u.last_login, u.created_at, COALESCE(m.is_enabled, 0) AS mfa_enabled FROM users u LEFT JOIN mfa_configs m ON m.user_id = u.id WHERE u.id = ?').get(req.params.id), null);
  if (!user) return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
  return res.json({ user });
});

router.put('/users/:id/role', validators.role, rejectInvalid, (req, res) => {
  const result = run((db) => db.prepare('UPDATE users SET role = ?, updated_at = unixepoch() WHERE id = ?').run(req.body.role, req.params.id), null);
  if (!result || result.changes === 0) return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
  audit({ userId: req.user.userId, eventType: 'ADMIN_ACTION', req, metadata: { action: 'SET_ROLE', target_user_id: req.params.id, role: req.body.role } });
  return res.json({ ok: true });
});

router.post('/users/:id/unlock', validators.userId, rejectInvalid, (req, res) => {
  const result = run((db) => db.prepare('UPDATE users SET is_locked = 0, failed_attempts = 0, updated_at = unixepoch() WHERE id = ?').run(req.params.id), null);
  if (!result || result.changes === 0) return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
  audit({ userId: req.params.id, eventType: 'ACCOUNT_UNLOCKED', req, metadata: { admin_user_id: req.user.userId, target_user_id: req.params.id } });
  audit({ userId: req.user.userId, eventType: 'ADMIN_ACTION', req, metadata: { action: 'UNLOCK_USER', target_user_id: req.params.id } });
  return res.json({ ok: true });
});

router.get('/audit-log', validators.pagination, validators.auditFilters, rejectInvalid, (req, res) => {
  const page = req.query.page || 1;
  const limit = req.query.limit || 25;
  const offset = (page - 1) * limit;
  const eventType = req.query.event_type || null;
  const userId = req.query.user_id || null;
  const rows = run((db) => db.prepare('SELECT * FROM audit_log WHERE (? IS NULL OR event_type = ?) AND (? IS NULL OR user_id = ?) ORDER BY created_at DESC LIMIT ? OFFSET ?').all(eventType, eventType, userId, userId, limit, offset), []);
  return res.json({ events: rows, page, limit });
});

router.get('/stats', (req, res) => {
  const stats = run((db) => ({
    totalUsers: db.prepare('SELECT COUNT(*) AS c FROM users').get().c,
    lockedAccounts: db.prepare('SELECT COUNT(*) AS c FROM users WHERE is_locked = 1').get().c,
    mfaEnabled: db.prepare('SELECT COUNT(*) AS c FROM mfa_configs WHERE is_enabled = 1').get().c,
    activeSessionsToday: db.prepare("SELECT COUNT(*) AS c FROM sessions WHERE is_revoked = 0 AND created_at >= unixepoch('now', 'start of day')").get().c
  }), { totalUsers: 0, lockedAccounts: 0, mfaEnabled: 0, activeSessionsToday: 0 });
  stats.mfaAdoption = stats.totalUsers ? Math.round((stats.mfaEnabled / stats.totalUsers) * 100) : 0;
  return res.json({ stats });
});

router.get('/security-posture', (req, res) => {
  return res.json({ stats: adminSecurityStats() });
});

router.get('/policy', (req, res) => {
  return res.json({ policy: getPolicy() });
});

router.put('/policy', validators.policyUpdate, rejectInvalid, (req, res) => {
  const policy = updatePolicy(req.body, req.user.userId);
  audit({ userId: req.user.userId, eventType: 'ADMIN_ACTION', req, metadata: { action: 'UPDATE_POLICY', policy } });
  return res.json({ policy });
});

router.get('/incidents', (req, res) => {
  const incidents = run((db) => {
    const rows = db.prepare("SELECT event_type, COUNT(*) AS count, MAX(created_at) AS last_at FROM audit_log WHERE event_type IN ('LOGIN_FAILURE','MFA_FAILURE','ACCOUNT_LOCKED','PRIVILEGE_ESCALATION_ATTEMPT','INVALID_TOKEN_ATTEMPT') GROUP BY event_type ORDER BY last_at DESC").all();
    return rows.map((row, index) => ({
      id: index + 1,
      type: row.event_type,
      title: row.event_type.replaceAll('_', ' ').toLowerCase(),
      severity: ['ACCOUNT_LOCKED', 'PRIVILEGE_ESCALATION_ATTEMPT', 'INVALID_TOKEN_ATTEMPT'].includes(row.event_type) ? 'high' : 'medium',
      count: row.count,
      lastEventAt: row.last_at,
      status: 'open'
    }));
  }, []);
  return res.json({ incidents });
});

router.post('/incidents/explain', validators.incidentExplain, rejectInvalid, async (req, res) => {
  const incidents = run((db) => db.prepare("SELECT event_type, COUNT(*) AS count, MAX(created_at) AS last_at FROM audit_log WHERE event_type IN ('LOGIN_FAILURE','MFA_FAILURE','ACCOUNT_LOCKED','PRIVILEGE_ESCALATION_ATTEMPT','INVALID_TOKEN_ATTEMPT') GROUP BY event_type ORDER BY last_at DESC").all(), []);
  const incident = incidents[req.body.incidentId - 1];
  if (!incident) return res.status(404).json({ error: 'Incident not found', code: 'INCIDENT_NOT_FOUND' });
  try {
    const result = await askGroq({ userId: req.user.userId, question: `Explain this SecureOS incident for an administrator and recommend next actions: ${JSON.stringify(incident)}` });
    return res.json(result);
  } catch (error) {
    return res.status(error.status || 502).json({ error: process.env.NODE_ENV === 'production' ? 'AI incident explanation failed' : `AI incident explanation failed: ${error.message}`, code: error.code || 'AI_REQUEST_FAILED' });
  }
});

module.exports = router;
