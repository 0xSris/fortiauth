const { run } = require('../db/database');

function audit({ userId = null, eventType, req = null, metadata = {} }) {
  return run((db) => db.prepare(
    'INSERT INTO audit_log (user_id, event_type, ip_address, user_agent, metadata) VALUES (?, ?, ?, ?, ?)'
  ).run(
    userId,
    eventType,
    req ? req.ip : null,
    req ? String(req.headers['user-agent'] || '').slice(0, 512) : null,
    JSON.stringify(metadata || {})
  ), null);
}

module.exports = { audit };
