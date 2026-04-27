const { run } = require('../db/database');

function parseDevice(userAgent = '') {
  const ua = String(userAgent);
  const browser = ua.includes('Edg/') ? 'Microsoft Edge'
    : ua.includes('Chrome/') ? 'Chrome'
      : ua.includes('Firefox/') ? 'Firefox'
        : ua.includes('Safari/') ? 'Safari'
          : 'Unknown browser';
  const os = ua.includes('Windows') ? 'Windows'
    : ua.includes('Mac OS') ? 'macOS'
      : ua.includes('Linux') ? 'Linux'
        : ua.includes('Android') ? 'Android'
          : ua.includes('iPhone') || ua.includes('iPad') ? 'iOS'
            : 'Unknown OS';
  return { browser, os };
}

function userSecurityOverview(userId) {
  return run((db) => {
    const user = db.prepare('SELECT id, username, role, is_locked, failed_attempts, last_login, created_at, updated_at FROM users WHERE id = ?').get(userId);
    const mfa = db.prepare('SELECT is_enabled, backup_codes, created_at FROM mfa_configs WHERE user_id = ?').get(userId);
    const sessions = db.prepare('SELECT id, user_agent, ip_address, created_at, expires_at FROM sessions WHERE user_id = ? AND is_revoked = 0 AND expires_at > unixepoch() ORDER BY created_at DESC').all(userId);
    const failures24h = db.prepare("SELECT COUNT(*) AS count FROM audit_log WHERE user_id = ? AND event_type IN ('LOGIN_FAILURE','MFA_FAILURE','INVALID_TOKEN_ATTEMPT') AND created_at >= unixepoch() - 86400").get(userId).count;
    const uniqueIps = new Set(sessions.map((s) => s.ip_address || 'unknown')).size;
    const backupCount = mfa && mfa.backup_codes ? JSON.parse(mfa.backup_codes).length : 0;
    let risk = 12;
    if (!mfa || !mfa.is_enabled) risk += 34;
    if (backupCount < 5) risk += 8;
    if (sessions.length > 3) risk += 10;
    if (uniqueIps > 1) risk += 12;
    if (failures24h) risk += Math.min(20, failures24h * 5);
    if (user && user.failed_attempts) risk += Math.min(12, user.failed_attempts * 3);
    if (user && user.is_locked) risk = 95;
    risk = Math.min(100, risk);
    const posture = [
      { key: 'mfa', label: 'TOTP multifactor authentication', status: mfa && mfa.is_enabled ? 'pass' : 'fail', detail: mfa && mfa.is_enabled ? 'Second factor is enforced for login.' : 'Enable TOTP to block password-only access.' },
      { key: 'backup', label: 'Emergency backup code reserve', status: backupCount >= 5 ? 'pass' : 'warn', detail: `${backupCount} unused backup codes remain.` },
      { key: 'sessions', label: 'Active session hygiene', status: sessions.length <= 3 ? 'pass' : 'warn', detail: `${sessions.length} active sessions are currently trusted.` },
      { key: 'failures', label: 'Recent failed auth attempts', status: failures24h === 0 ? 'pass' : 'warn', detail: `${failures24h} failed security events in the last 24 hours.` },
      { key: 'lockout', label: 'Account lockout protection', status: user && !user.is_locked ? 'pass' : 'fail', detail: user && user.is_locked ? 'Account is locked by policy.' : 'Lockout policy is ready after 5 failures.' }
    ];
    return {
      risk,
      riskLevel: risk >= 70 ? 'critical' : risk >= 40 ? 'elevated' : 'guarded',
      posture,
      mfa: { enabled: Boolean(mfa && mfa.is_enabled), backupCodesRemaining: backupCount },
      sessions: sessions.map((s) => ({ ...s, device: parseDevice(s.user_agent) })),
      threatSignals: { failures24h, uniqueIps, activeSessions: sessions.length }
    };
  }, { risk: 100, riskLevel: 'unknown', posture: [], mfa: { enabled: false, backupCodesRemaining: 0 }, sessions: [], threatSignals: {} });
}

function adminSecurityStats() {
  return run((db) => {
    const totalUsers = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
    const mfaEnabled = db.prepare('SELECT COUNT(*) AS c FROM mfa_configs WHERE is_enabled = 1').get().c;
    const lockedAccounts = db.prepare('SELECT COUNT(*) AS c FROM users WHERE is_locked = 1').get().c;
    const activeSessions = db.prepare('SELECT COUNT(*) AS c FROM sessions WHERE is_revoked = 0 AND expires_at > unixepoch()').get().c;
    const failures24h = db.prepare("SELECT COUNT(*) AS c FROM audit_log WHERE event_type IN ('LOGIN_FAILURE','MFA_FAILURE','INVALID_TOKEN_ATTEMPT','PRIVILEGE_ESCALATION_ATTEMPT') AND created_at >= unixepoch() - 86400").get().c;
    const privilegeAttempts = db.prepare("SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'PRIVILEGE_ESCALATION_ATTEMPT' AND created_at >= unixepoch() - 86400").get().c;
    const refreshRotations = db.prepare("SELECT COUNT(*) AS c FROM audit_log WHERE event_type = 'TOKEN_REFRESH' AND created_at >= unixepoch() - 86400").get().c;
    const recent = db.prepare('SELECT event_type, created_at FROM audit_log ORDER BY created_at DESC LIMIT 12').all();
    return {
      totalUsers,
      mfaEnabled,
      lockedAccounts,
      activeSessions,
      failures24h,
      privilegeAttempts,
      refreshRotations,
      mfaAdoption: totalUsers ? Math.round((mfaEnabled / totalUsers) * 100) : 0,
      postureScore: Math.max(0, Math.min(100, 100 - lockedAccounts * 8 - failures24h * 4 - privilegeAttempts * 12 + (totalUsers ? Math.round((mfaEnabled / totalUsers) * 20) : 0))),
      recent
    };
  }, { totalUsers: 0, mfaEnabled: 0, lockedAccounts: 0, activeSessions: 0, failures24h: 0, privilegeAttempts: 0, refreshRotations: 0, mfaAdoption: 0, postureScore: 0, recent: [] });
}

module.exports = { parseDevice, userSecurityOverview, adminSecurityStats };
