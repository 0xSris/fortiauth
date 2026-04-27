const { run } = require('../db/database');

const defaults = {
  requireMfaForAdmins: true,
  lockoutThreshold: 5,
  sessionMaxHours: 168,
  staleSessionHours: 24,
  emailOtpTtlMinutes: 10,
  riskAlertThreshold: 70
};

function getPolicy() {
  return run((db) => {
    const rows = db.prepare('SELECT key, value FROM policy_settings').all();
    const policy = { ...defaults };
    for (const row of rows) {
      try {
        policy[row.key] = JSON.parse(row.value);
      } catch {
        policy[row.key] = row.value;
      }
    }
    return policy;
  }, { ...defaults });
}

function updatePolicy(nextPolicy, adminId) {
  const allowed = Object.keys(defaults);
  return run((db) => {
    const tx = db.transaction(() => {
      for (const key of allowed) {
        if (Object.prototype.hasOwnProperty.call(nextPolicy, key)) {
          db.prepare('INSERT INTO policy_settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, unixepoch()) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = unixepoch()')
            .run(key, JSON.stringify(nextPolicy[key]), adminId);
        }
      }
    });
    tx();
    return getPolicy();
  }, getPolicy());
}

module.exports = { getPolicy, updatePolicy };
