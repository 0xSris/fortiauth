const express = require('express');
const { run } = require('../db/database');
const { validators } = require('../utils/validators');
const { rejectInvalid } = require('../middleware/sanitize');
const { requireAuth } = require('../middleware/auth');
const { loginLimiter, registerLimiter, passwordResetLimiter } = require('../middleware/rateLimiter');
const authService = require('../services/authService');
const { audit } = require('../services/auditService');
const { getMfaConfig, setupMfa, verifyTotp, verifyBackupCode, enableMfa, disableMfa, rotateBackupCodes } = require('../services/mfaService');
const { sha256, randomToken } = require('../utils/crypto');
const { hashPassword, validatePassword } = require('../services/passwordService');

const router = express.Router();
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

router.post('/register', registerLimiter, validators.register, rejectInvalid, asyncHandler(async (req, res) => {
  const result = await authService.register(req.body, req);
  res.status(result.status).json(result.body);
}));

router.post('/login', loginLimiter, validators.login, rejectInvalid, asyncHandler(async (req, res) => {
  const result = await authService.login(req.body, req);
  if (result.refreshToken) authService.setRefreshCookie(res, result.refreshToken);
  res.status(result.status).json(result.body);
}));

router.post('/mfa/login', loginLimiter, validators.mfaLogin, rejectInvalid, asyncHandler(async (req, res) => {
  try {
    const userId = authService.verifyTempToken(req.body.tempToken);
    const user = run((db) => db.prepare('SELECT * FROM users WHERE id = ?').get(userId), null);
    const config = getMfaConfig(userId);
    const ok = verifyTotp(config, req.body.code) || await verifyBackupCode(config, req.body.code);
    if (!user || !ok) {
      audit({ userId, eventType: 'MFA_FAILURE', req });
      return res.status(401).json({ error: 'Invalid MFA code', code: 'MFA_INVALID' });
    }
    const session = authService.createSession(userId, req);
    run((db) => db.prepare('UPDATE users SET failed_attempts = 0, last_login = unixepoch(), updated_at = unixepoch() WHERE id = ?').run(userId), null);
    audit({ userId, eventType: 'MFA_SUCCESS', req });
    audit({ userId, eventType: 'LOGIN_SUCCESS', req, metadata: { sessionId: session.sessionId } });
    authService.setRefreshCookie(res, session.refreshToken);
    return res.json({ accessToken: session.accessToken, user: authService.publicUser(user), sessionId: session.sessionId });
  } catch {
    return res.status(401).json({ error: 'Invalid MFA session', code: 'MFA_SESSION_INVALID' });
  }
}));

router.post('/logout', requireAuth, (req, res) => {
  run((db) => db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ?').run(req.user.sessionId), null);
  audit({ userId: req.user.userId, eventType: 'LOGOUT', req, metadata: { sessionId: req.user.sessionId } });
  authService.clearRefreshCookie(res);
  res.json({ ok: true });
});

router.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'Missing refresh token', code: 'REFRESH_REQUIRED' });
  const tokenHash = sha256(token);
  const session = run((db) => db.prepare('SELECT * FROM sessions WHERE refresh_token = ?').get(tokenHash), null);
  if (!session || session.is_revoked || session.expires_at <= authService.now()) {
    audit({ eventType: 'INVALID_TOKEN_ATTEMPT', req, metadata: { kind: 'refresh' } });
    return res.status(401).json({ error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
  }
  run((db) => db.prepare('UPDATE sessions SET is_revoked = 1 WHERE id = ?').run(session.id), null);
  const nextSession = authService.createSession(session.user_id, req);
  audit({ userId: session.user_id, eventType: 'TOKEN_REFRESH', req, metadata: { oldSessionId: session.id, newSessionId: nextSession.sessionId } });
  authService.setRefreshCookie(res, nextSession.refreshToken);
  return res.json({ accessToken: nextSession.accessToken, sessionId: nextSession.sessionId });
});

router.post('/mfa/setup', requireAuth, asyncHandler(async (req, res) => {
  const user = run((db) => db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.user.userId), null);
  if (!user) return res.status(404).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
  try {
    const payload = await setupMfa(user);
    return res.json(payload);
  } catch {
    return res.status(500).json({ error: 'Unable to setup MFA', code: 'MFA_SETUP_FAILED' });
  }
}));

router.post('/mfa/verify', requireAuth, validators.mfaVerify, rejectInvalid, (req, res) => {
  const config = getMfaConfig(req.user.userId);
  if (!verifyTotp(config, req.body.code)) {
    audit({ userId: req.user.userId, eventType: 'MFA_FAILURE', req });
    return res.status(401).json({ error: 'Invalid MFA code', code: 'MFA_INVALID' });
  }
  enableMfa(req.user.userId);
  audit({ userId: req.user.userId, eventType: 'MFA_ENABLED', req });
  return res.json({ ok: true });
});

router.post('/mfa/disable', requireAuth, validators.mfaVerify, rejectInvalid, (req, res) => {
  const config = getMfaConfig(req.user.userId);
  if (!verifyTotp(config, req.body.code)) {
    audit({ userId: req.user.userId, eventType: 'MFA_FAILURE', req });
    return res.status(401).json({ error: 'Invalid MFA code', code: 'MFA_INVALID' });
  }
  disableMfa(req.user.userId);
  audit({ userId: req.user.userId, eventType: 'MFA_DISABLED', req });
  return res.json({ ok: true });
});

router.post('/mfa/backup-codes/rotate', requireAuth, validators.mfaVerify, rejectInvalid, asyncHandler(async (req, res) => {
  const config = getMfaConfig(req.user.userId);
  if (!config || !config.is_enabled || !verifyTotp(config, req.body.code)) {
    audit({ userId: req.user.userId, eventType: 'MFA_FAILURE', req, metadata: { action: 'ROTATE_BACKUP_CODES' } });
    return res.status(401).json({ error: 'Invalid MFA code', code: 'MFA_INVALID' });
  }
  const backupCodes = await rotateBackupCodes(req.user.userId);
  audit({ userId: req.user.userId, eventType: 'MFA_SUCCESS', req, metadata: { action: 'ROTATE_BACKUP_CODES' } });
  return res.json({ backupCodes });
}));

router.post('/password-reset/request', passwordResetLimiter, validators.resetRequest, rejectInvalid, (req, res) => {
  const user = run((db) => db.prepare('SELECT id FROM users WHERE email = ?').get(req.body.email), null);
  if (user) {
    const token = randomToken(32);
    run((db) => db.prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)').run(user.id, sha256(token), authService.now() + 3600), null);
    audit({ userId: user.id, eventType: 'PASSWORD_RESET_REQUEST', req });
    if (process.env.NODE_ENV !== 'production') return res.json({ ok: true, resetToken: token });
  }
  return res.json({ ok: true });
});

router.post('/password-reset/confirm', passwordResetLimiter, validators.resetConfirm, rejectInvalid, asyncHandler(async (req, res) => {
  const validationError = validatePassword(req.body.password);
  if (validationError) return res.status(400).json({ error: validationError, code: 'WEAK_PASSWORD' });
  const row = run((db) => db.prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ?').get(sha256(req.body.token)), null);
  if (!row || row.used || row.expires_at <= authService.now()) return res.status(400).json({ error: 'Invalid reset token', code: 'INVALID_RESET_TOKEN' });
  const hash = await hashPassword(req.body.password);
  run((db) => {
    const tx = db.transaction(() => {
      db.prepare('UPDATE users SET password_hash = ?, failed_attempts = 0, is_locked = 0, updated_at = unixepoch() WHERE id = ?').run(hash, row.user_id);
      db.prepare('UPDATE password_reset_tokens SET used = 1 WHERE id = ?').run(row.id);
      db.prepare('UPDATE sessions SET is_revoked = 1 WHERE user_id = ?').run(row.user_id);
    });
    tx();
  }, null);
  audit({ userId: row.user_id, eventType: 'PASSWORD_RESET_SUCCESS', req });
  return res.json({ ok: true });
}));

module.exports = router;
