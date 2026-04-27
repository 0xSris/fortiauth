const { run } = require('../db/database');
const { userSecurityOverview } = require('./securityService');
const { audit } = require('./auditService');

const scenarios = {
  brute_force: {
    title: 'Brute-force lockout defense',
    eventType: 'LOGIN_FAILURE',
    severity: 'high',
    steps: [
      'Rejects malformed or oversized credential payloads before business logic.',
      'Counts consecutive failed attempts server-side.',
      'Locks the account at the fifth failed attempt.',
      'Writes LOGIN_FAILURE and ACCOUNT_LOCKED events to the audit log.'
    ],
    result: 'Credential stuffing is rate-limited, audited, and stopped by account lockout.'
  },
  privilege_escalation: {
    title: 'Privilege escalation shield',
    eventType: 'PRIVILEGE_ESCALATION_ATTEMPT',
    severity: 'critical',
    steps: [
      'Detects client-supplied role fields and role headers.',
      'Rejects the request before route business logic executes.',
      'Fetches admin role fresh from SQLite on every admin call.',
      'Logs PRIVILEGE_ESCALATION_ATTEMPT with request metadata.'
    ],
    result: 'Roles cannot be promoted from JWT payloads, headers, or request bodies.'
  },
  buffer_overflow: {
    title: 'Input-size and buffer safety',
    eventType: 'INVALID_TOKEN_ATTEMPT',
    severity: 'medium',
    steps: [
      'Caps JSON and URL-encoded bodies at 10kb.',
      'Applies strict max lengths to username, email, password, token, and MFA fields.',
      'Rejects invalid input with 400 before service logic.',
      'Uses memory-safe JavaScript strings and parameterized SQLite calls.'
    ],
    result: 'Oversized and malformed inputs are rejected at the edge instead of being processed.'
  },
  trapdoor_scan: {
    title: 'Hidden trapdoor prevention',
    eventType: 'ADMIN_ACTION',
    severity: 'high',
    steps: [
      'No hardcoded user credentials or backdoor accounts are created by the app.',
      'Admin creation is isolated to seed.js and guarded by ADMIN_SEED_KEY.',
      'All SQL statements use bound parameters.',
      'Admin actions are audited with target identifiers.'
    ],
    result: 'Administrative access is explicit, auditable, and not hidden in runtime code paths.'
  },
  token_replay: {
    title: 'Refresh token replay resistance',
    eventType: 'INVALID_TOKEN_ATTEMPT',
    severity: 'high',
    steps: [
      'Stores only SHA-256 hashes of refresh tokens.',
      'Rotates refresh tokens on every refresh call.',
      'Revokes the previous session row after rotation.',
      'Requires a live, non-revoked session for access-token use.'
    ],
    result: 'A stolen old refresh token cannot be reused after rotation.'
  }
};

function listScenarios() {
  return Object.entries(scenarios).map(([id, scenario]) => ({
    id,
    title: scenario.title,
    severity: scenario.severity,
    result: scenario.result
  }));
}

function simulateScenario({ scenarioId, userId, req }) {
  const scenario = scenarios[scenarioId];
  if (!scenario) return null;
  audit({
    userId,
    eventType: scenario.eventType,
    req,
    metadata: {
      demo: true,
      scenario: scenarioId,
      title: scenario.title,
      simulated: true
    }
  });
  return {
    id: scenarioId,
    title: scenario.title,
    severity: scenario.severity,
    steps: scenario.steps.map((step, index) => ({
      order: index + 1,
      status: 'done',
      text: step
    })),
    result: scenario.result,
    auditEvent: scenario.eventType
  };
}

function securityReport(userId) {
  const overview = userSecurityOverview(userId);
  const user = run((db) => db.prepare('SELECT username, email, role, created_at, last_login FROM users WHERE id = ?').get(userId), null);
  const recentEvents = run((db) => db.prepare('SELECT event_type, metadata, created_at FROM audit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 10').all(userId), []);
  const controls = [
    { name: 'JWT access token expiry', status: 'implemented', evidence: 'Access tokens expire via JWT_EXPIRES_IN and include userId plus sessionId only.' },
    { name: 'Refresh token rotation', status: 'implemented', evidence: 'Refresh tokens are SHA-256 hashed in SQLite and old sessions are revoked on refresh.' },
    { name: 'TOTP MFA', status: overview.mfa.enabled ? 'enforced' : 'available', evidence: overview.mfa.enabled ? 'MFA is enabled for this account.' : 'MFA setup endpoint and encrypted secret storage are available.' },
    { name: 'Account lockout', status: 'implemented', evidence: 'Five consecutive failed attempts lock the account until admin unlock.' },
    { name: 'Privilege escalation defense', status: 'implemented', evidence: 'Roles are fetched from DB, not trusted from clients or JWT role claims.' },
    { name: 'Buffer overflow prevention', status: 'implemented', evidence: 'Body size is capped at 10kb and express-validator enforces field max lengths.' },
    { name: 'Hidden trapdoor prevention', status: 'implemented', evidence: 'Admin creation is isolated to seed.js and requires ADMIN_SEED_KEY.' }
  ];
  const recommendations = overview.posture
    .filter((item) => item.status !== 'pass')
    .map((item) => ({ control: item.label, action: item.detail }));
  if (!recommendations.length) {
    recommendations.push({ control: 'Continuous monitoring', action: 'Maintain MFA, review audit events, and rotate credentials periodically.' });
  }
  return {
    generatedAt: Math.floor(Date.now() / 1000),
    subject: user,
    executiveSummary: `SecureOS currently rates this identity at ${overview.risk}/100 risk (${overview.riskLevel}). The framework demonstrates MFA, lockout, refresh-token rotation, input hardening, privilege controls, and auditability.`,
    risk: { score: overview.risk, level: overview.riskLevel },
    controls,
    recommendations,
    recentEvents,
    demoScript: [
      'Register or sign in as a user.',
      'Show the risk score and explain why MFA changes it.',
      'Run each Demo Lab scenario and point to the generated audit event.',
      'Enable MFA, rotate backup codes, and revoke a session.',
      'Open Admin Governance to show audit stream and identity inventory.'
    ]
  };
}

module.exports = { listScenarios, simulateScenario, securityReport };
