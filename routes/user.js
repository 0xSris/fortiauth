const express = require('express');
const { run } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { validators } = require('../utils/validators');
const { rejectInvalid } = require('../middleware/sanitize');
const { verifyPassword, hashPassword, validatePassword } = require('../services/passwordService');
const { audit } = require('../services/auditService');
const { userSecurityOverview } = require('../services/securityService');
const { askGroq } = require('../services/aiService');
const { listScenarios, simulateScenario, securityReport } = require('../services/demoService');
const { createAndSendOtp, verifyOtp } = require('../services/emailOtpService');
const { deviceTrust, markTrusted, riskTimeline, securityChecklist, recoveryVault, securityGrade } = require('../services/intelligenceService');

const router = express.Router();
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
router.use(requireAuth);

router.get('/me', (req, res) => {
  const user = run((db) => db.prepare('SELECT u.id, u.username, u.email, u.role, u.last_login, u.created_at, COALESCE(m.is_enabled, 0) AS mfa_enabled FROM users u LEFT JOIN mfa_configs m ON m.user_id = u.id WHERE u.id = ?').get(req.user.userId), null);
  if (!user) return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
  return res.json({ user });
});

router.get('/security-overview', (req, res) => {
  return res.json({ overview: userSecurityOverview(req.user.userId) });
});

router.get('/security-intelligence', (req, res) => {
  return res.json({
    grade: securityGrade(req.user.userId),
    timeline: riskTimeline(req.user.userId),
    checklist: securityChecklist(req.user.userId),
    recoveryVault: recoveryVault(req.user.userId),
    devices: deviceTrust(req.user.userId)
  });
});

router.post('/email-otp/send', validators.emailOtpSend, rejectInvalid, asyncHandler(async (req, res) => {
  const result = await createAndSendOtp(req.user.userId, req.body.purpose || 'email_verification');
  return res.json(result);
}));

router.post('/email-otp/verify', validators.emailOtpVerify, rejectInvalid, (req, res) => {
  const ok = verifyOtp(req.user.userId, req.body.otp, req.body.purpose || 'email_verification');
  if (!ok) return res.status(400).json({ error: 'Invalid or expired OTP', code: 'INVALID_EMAIL_OTP' });
  audit({ userId: req.user.userId, eventType: 'MFA_SUCCESS', req, metadata: { factor: 'email_otp', purpose: req.body.purpose || 'email_verification' } });
  return res.json({ ok: true });
});

router.post('/devices/trust', validators.trustDevice, rejectInvalid, (req, res) => {
  const result = markTrusted(req.user.userId, req.body.sessionId, req.body.label || 'Trusted device');
  if (!result) return res.status(404).json({ error: 'Session not found', code: 'SESSION_NOT_FOUND' });
  audit({ userId: req.user.userId, eventType: 'ADMIN_ACTION', req, metadata: { action: 'TRUST_DEVICE', sessionId: req.body.sessionId } });
  return res.json({ device: result });
});

router.get('/demo/showcase', (req, res) => {
  return res.json({
    scenarios: listScenarios(),
    talkingPoints: [
      'JWT contains only userId and sessionId; role is always fetched fresh from SQLite.',
      'MFA secrets are encrypted at rest with AES-256-GCM.',
      'Refresh tokens are stored only as SHA-256 hashes and rotated on every refresh.',
      'The app rejects oversized bodies and invalid field lengths before business logic.',
      'Every meaningful security event is written to audit_log.'
    ]
  });
});

router.post('/demo/simulate', validators.demoScenario, rejectInvalid, (req, res) => {
  const result = simulateScenario({ scenarioId: req.body.scenario, userId: req.user.userId, req });
  if (!result) return res.status(400).json({ error: 'Unknown demo scenario', code: 'UNKNOWN_SCENARIO' });
  return res.json({ simulation: result });
});

router.get('/security-report', (req, res) => {
  return res.json({ report: securityReport(req.user.userId) });
});

router.post('/ai/ask', validators.aiAsk, rejectInvalid, asyncHandler(async (req, res) => {
  try {
    const result = await askGroq({ userId: req.user.userId, question: req.body.question });
    return res.json(result);
  } catch (error) {
    if (error.code === 'GROQ_NOT_CONFIGURED') {
      return res.status(503).json({ error: 'Groq API key is not configured on the server', code: 'GROQ_NOT_CONFIGURED' });
    }
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'AI request timed out', code: 'AI_TIMEOUT' });
    }
    return res.status(error.status || 502).json({
      error: process.env.NODE_ENV === 'production' ? 'AI assistant request failed' : `AI assistant request failed: ${error.message}`,
      code: error.code || 'AI_REQUEST_FAILED'
    });
  }
}));

router.put('/me/password', validators.changePassword, rejectInvalid, asyncHandler(async (req, res) => {
  const user = run((db) => db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.userId), null);
  if (!user || !(await verifyPassword(user.password_hash, req.body.currentPassword))) {
    return res.status(401).json({ error: 'Current password is incorrect', code: 'INVALID_PASSWORD' });
  }
  const validationError = validatePassword(req.body.password);
  if (validationError) return res.status(400).json({ error: validationError, code: 'WEAK_PASSWORD' });
  const hash = await hashPassword(req.body.password);
  run((db) => db.prepare('UPDATE users SET password_hash = ?, updated_at = unixepoch() WHERE id = ?').run(hash, req.user.userId), null);
  audit({ userId: req.user.userId, eventType: 'PASSWORD_CHANGED', req });
  return res.json({ ok: true });
}));

router.get('/sessions', (req, res) => {
  const sessions = run((db) => db.prepare('SELECT id, user_agent, ip_address, expires_at, created_at, is_revoked FROM sessions WHERE user_id = ? AND is_revoked = 0 AND expires_at > unixepoch() ORDER BY created_at DESC').all(req.user.userId), []);
  return res.json({ sessions, currentSessionId: req.user.sessionId });
});

router.delete('/sessions/:id', validators.sessionId, rejectInvalid, (req, res) => {
  const result = run((db) => db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.userId), null);
  if (!result || result.changes === 0) return res.status(404).json({ error: 'Session not found', code: 'SESSION_NOT_FOUND' });
  audit({ userId: req.user.userId, eventType: 'SESSION_REVOKED', req, metadata: { sessionId: req.params.id } });
  return res.json({ ok: true });
});

module.exports = router;
