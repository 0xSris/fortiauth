const { validationResult } = require('express-validator');
const { audit } = require('../services/auditService');

function rejectInvalid(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Invalid request input', code: 'VALIDATION_ERROR', details: errors.array().map((e) => ({ field: e.path, message: e.msg })) });
  }
  return next();
}

function detectPrivilegeEscalation(req, res, next) {
  const hasRoleBody = req.body && Object.prototype.hasOwnProperty.call(req.body, 'role') && !req.path.match(/^\/admin\/users\/\d+\/role$/);
  const hasRoleHeader = typeof req.headers['x-role'] !== 'undefined' || typeof req.headers.role !== 'undefined';
  if (hasRoleBody || hasRoleHeader) {
    audit({
      userId: req.user ? req.user.userId : null,
      eventType: 'PRIVILEGE_ESCALATION_ATTEMPT',
      req,
      metadata: { path: req.originalUrl, method: req.method }
    });
    return res.status(403).json({ error: 'Privilege escalation attempt rejected', code: 'PRIVILEGE_ESCALATION_ATTEMPT' });
  }
  return next();
}

module.exports = { rejectInvalid, detectPrivilegeEscalation };
