const { run } = require('../db/database');
const { sha256 } = require('../utils/crypto');
const { userSecurityOverview, parseDevice } = require('./securityService');
const { getPolicy } = require('./policyService');

function sessionFingerprint(session) {
  return sha256(`${session.user_agent || ''}|${session.ip_address || ''}`);
}

function trustForSession(session, trusted, policy) {
  const ageHours = (Math.floor(Date.now() / 1000) - session.created_at) / 3600;
  const device = parseDevice(session.user_agent);
  const isPrivate = /^(::1|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(session.ip_address || '');
  let score = 82;
  if (!trusted) score -= 18;
  if (ageHours > policy.staleSessionHours) score -= 18;
  if (!isPrivate) score -= 8;
  const trust = score >= 75 ? 'trusted' : score >= 55 ? 'new' : 'suspicious';
  return { score: Math.max(0, Math.round(score)), trust, ageHours: Math.round(ageHours), device, isPrivateNetwork: isPrivate };
}

function deviceTrust(userId) {
  const policy = getPolicy();
  return run((db) => {
    const sessions = db.prepare('SELECT * FROM sessions WHERE user_id = ? AND is_revoked = 0 AND expires_at > unixepoch() ORDER BY created_at DESC').all(userId);
    const trustedRows = db.prepare('SELECT fingerprint, label, trust_level FROM trusted_devices WHERE user_id = ?').all(userId);
    const trusted = new Map(trustedRows.map((row) => [row.fingerprint, row]));
    return sessions.map((session) => {
      const fingerprint = sessionFingerprint(session);
      return {
        sessionId: session.id,
        fingerprint,
        userAgent: session.user_agent,
        ipAddress: session.ip_address,
        createdAt: session.created_at,
        ...trustForSession(session, trusted.get(fingerprint), policy)
      };
    });
  }, []);
}

function markTrusted(userId, sessionId, label = 'Trusted device') {
  return run((db) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND user_id = ?').get(sessionId, userId);
    if (!session) return null;
    const fingerprint = sessionFingerprint(session);
    db.prepare('INSERT INTO trusted_devices (user_id, fingerprint, label, trust_level, last_seen) VALUES (?, ?, ?, ?, unixepoch()) ON CONFLICT(user_id, fingerprint) DO UPDATE SET label = excluded.label, trust_level = excluded.trust_level, last_seen = unixepoch()')
      .run(userId, fingerprint, label, 'trusted');
    return { fingerprint, label, trust: 'trusted' };
  }, null);
}

function riskTimeline(userId) {
  const overview = userSecurityOverview(userId);
  const events = run((db) => db.prepare('SELECT event_type, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at ASC LIMIT 40').all(userId), []);
  let score = 35;
  const weights = {
    REGISTER: 2,
    LOGIN_SUCCESS: -2,
    LOGIN_FAILURE: 8,
    MFA_FAILURE: 10,
    MFA_ENABLED: -20,
    MFA_DISABLED: 22,
    PASSWORD_CHANGED: -8,
    TOKEN_REFRESH: -1,
    SESSION_REVOKED: -6,
    INVALID_TOKEN_ATTEMPT: 14,
    PRIVILEGE_ESCALATION_ATTEMPT: 25,
    ACCOUNT_LOCKED: 20
  };
  const points = events.map((event) => {
    score = Math.max(0, Math.min(100, score + (weights[event.event_type] || 0)));
    return { at: event.created_at, event: event.event_type, score };
  });
  points.push({ at: Math.floor(Date.now() / 1000), event: 'CURRENT_POSTURE', score: overview.risk });
  return points;
}

function securityChecklist(userId) {
  const overview = userSecurityOverview(userId);
  return [
    { key: 'mfa', label: 'Enable multifactor authentication', done: overview.mfa.enabled, impact: 'Removes password-only access.' },
    { key: 'backup', label: 'Maintain backup code reserve', done: overview.mfa.backupCodesRemaining >= 5, impact: 'Keeps emergency recovery available.' },
    { key: 'sessions', label: 'Revoke stale sessions', done: overview.threatSignals.activeSessions <= 3, impact: 'Reduces active token surface.' },
    { key: 'failures', label: 'Review failed authentication events', done: overview.threatSignals.failures24h === 0, impact: 'Catches brute-force activity early.' },
    { key: 'report', label: 'Generate security evidence report', done: false, impact: 'Creates proof of implemented controls.' }
  ];
}

function recoveryVault(userId) {
  const mfa = run((db) => db.prepare('SELECT is_enabled, backup_codes, created_at FROM mfa_configs WHERE user_id = ?').get(userId), null);
  const count = mfa && mfa.backup_codes ? JSON.parse(mfa.backup_codes).length : 0;
  return {
    mfaEnabled: Boolean(mfa && mfa.is_enabled),
    backupCodesRemaining: count,
    status: count >= 7 ? 'healthy' : count >= 3 ? 'low' : 'critical',
    lastRotatedAt: mfa ? mfa.created_at : null
  };
}

function securityGrade(userId) {
  const overview = userSecurityOverview(userId);
  const numeric = Math.max(0, 100 - overview.risk);
  const grade = numeric >= 90 ? 'A' : numeric >= 80 ? 'B' : numeric >= 70 ? 'C' : numeric >= 60 ? 'D' : 'F';
  return { grade, score: numeric, risk: overview.risk, level: overview.riskLevel };
}

module.exports = { deviceTrust, markTrusted, riskTimeline, securityChecklist, recoveryVault, securityGrade };
