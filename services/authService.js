const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { run } = require('../db/database');
const { randomToken, sha256 } = require('../utils/crypto');
const { hashPassword, verifyPassword, validatePassword } = require('./passwordService');
const { audit } = require('./auditService');

const now = () => Math.floor(Date.now() / 1000);
const refreshDays = () => Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS || 7);
const jwtSecret = () => process.env.JWT_SECRET || 'development-jwt-secret-change-me';

function signAccessToken(userId, sessionId) {
  return jwt.sign({ userId, sessionId }, jwtSecret(), { expiresIn: process.env.JWT_EXPIRES_IN || '15m' });
}

function signTempToken(userId) {
  return jwt.sign({ userId, purpose: 'mfa-login' }, jwtSecret(), { expiresIn: '5m' });
}

function verifyTempToken(tempToken) {
  const payload = jwt.verify(tempToken, jwtSecret());
  if (payload.purpose !== 'mfa-login') throw new Error('Invalid temp token');
  return payload.userId;
}

function createSession(userId, req) {
  const refreshToken = randomToken(32);
  const sessionId = uuidv4();
  const expiresAt = now() + refreshDays() * 86400;
  const inserted = run((db) => db.prepare(
    'INSERT INTO sessions (id, user_id, refresh_token, user_agent, ip_address, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(sessionId, userId, sha256(refreshToken), String(req.headers['user-agent'] || '').slice(0, 512), req.ip, expiresAt), null);
  if (!inserted) throw new Error('Unable to create session');
  return { sessionId, refreshToken, expiresAt, accessToken: signAccessToken(userId, sessionId) };
}

async function register({ username, email, password }, req) {
  const validationError = validatePassword(password);
  if (validationError) return { status: 400, body: { error: validationError, code: 'WEAK_PASSWORD' } };
  const passwordHash = await hashPassword(password);
  const result = run((db) => db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)').run(username, email, passwordHash), null);
  if (!result) return { status: 409, body: { error: 'Username or email already exists', code: 'USER_EXISTS' } };
  audit({ userId: result.lastInsertRowid, eventType: 'REGISTER', req });
  return { status: 201, body: { id: result.lastInsertRowid, username, email } };
}

async function login({ username, password }, req) {
  const user = run((db) => db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, username), null);
  if (!user) {
    audit({ eventType: 'LOGIN_FAILURE', req, metadata: { username } });
    return { status: 401, body: { error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' } };
  }
  if (user.is_locked) return { status: 403, body: { error: 'Account locked. Contact admin.', code: 'ACCOUNT_LOCKED' } };
  const ok = await verifyPassword(user.password_hash, password);
  if (!ok) {
    const attempts = user.failed_attempts + 1;
    run((db) => db.prepare('UPDATE users SET failed_attempts = ?, is_locked = CASE WHEN ? >= 5 THEN 1 ELSE is_locked END, updated_at = unixepoch() WHERE id = ?').run(attempts, attempts, user.id), null);
    audit({ userId: user.id, eventType: 'LOGIN_FAILURE', req, metadata: { username, attempts } });
    if (attempts >= 5) audit({ userId: user.id, eventType: 'ACCOUNT_LOCKED', req, metadata: { username } });
    return { status: attempts >= 5 ? 403 : 401, body: { error: attempts >= 5 ? 'Account locked. Contact admin.' : 'Invalid credentials', code: attempts >= 5 ? 'ACCOUNT_LOCKED' : 'INVALID_CREDENTIALS' } };
  }
  const mfa = run((db) => db.prepare('SELECT is_enabled FROM mfa_configs WHERE user_id = ?').get(user.id), null);
  if (mfa && mfa.is_enabled) return { status: 200, body: { requiresMfa: true, tempToken: signTempToken(user.id) } };
  const session = createSession(user.id, req);
  run((db) => db.prepare('UPDATE users SET failed_attempts = 0, last_login = unixepoch(), updated_at = unixepoch() WHERE id = ?').run(user.id), null);
  audit({ userId: user.id, eventType: 'LOGIN_SUCCESS', req, metadata: { sessionId: session.sessionId } });
  return { status: 200, body: { accessToken: session.accessToken, user: publicUser(user), sessionId: session.sessionId }, refreshToken: session.refreshToken };
}

function publicUser(user) {
  return { id: user.id, username: user.username, email: user.email, role: user.role, last_login: user.last_login, created_at: user.created_at };
}

function setRefreshCookie(res, token) {
  const sameSite = String(process.env.REFRESH_COOKIE_SAMESITE || (process.env.NODE_ENV === 'production' ? 'none' : 'strict')).toLowerCase();
  const secure = process.env.REFRESH_COOKIE_SECURE
    ? process.env.REFRESH_COOKIE_SECURE === 'true'
    : process.env.NODE_ENV === 'production' || sameSite === 'none';
  res.cookie('refreshToken', token, {
    httpOnly: true,
    secure,
    sameSite,
    maxAge: refreshDays() * 86400 * 1000,
    path: '/api/auth'
  });
}

function clearRefreshCookie(res) {
  const sameSite = String(process.env.REFRESH_COOKIE_SAMESITE || (process.env.NODE_ENV === 'production' ? 'none' : 'strict')).toLowerCase();
  const secure = process.env.REFRESH_COOKIE_SECURE
    ? process.env.REFRESH_COOKIE_SECURE === 'true'
    : process.env.NODE_ENV === 'production' || sameSite === 'none';
  res.clearCookie('refreshToken', { httpOnly: true, secure, sameSite, path: '/api/auth' });
}

module.exports = { register, login, createSession, signAccessToken, verifyTempToken, publicUser, setRefreshCookie, clearRefreshCookie, now };
