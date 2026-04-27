const { body, param, query } = require('express-validator');
const { commonPasswords } = require('./commonPasswords');

const passwordRules = body('password')
  .isString().isLength({ min: 8, max: 128 })
  .matches(/[a-z]/).withMessage('Password must include lowercase')
  .matches(/[A-Z]/).withMessage('Password must include uppercase')
  .matches(/[0-9]/).withMessage('Password must include digit')
  .matches(/[^A-Za-z0-9]/).withMessage('Password must include special character')
  .custom((value) => !commonPasswords.has(String(value).toLowerCase()))
  .withMessage('Password is too common');

const username = body('username').isString().trim().isLength({ min: 3, max: 32 }).matches(/^[a-zA-Z0-9_.-]+$/);
const email = body('email').isEmail().normalizeEmail().isLength({ max: 254 });
const code = body('code').isString().matches(/^\d{6}$/);
const token = body('token').isString().isLength({ min: 20, max: 256 });
const idParam = param('id').isString().isLength({ min: 1, max: 64 }).matches(/^[a-zA-Z0-9-]+$/);
const intIdParam = param('id').isInt({ min: 1 }).toInt();

const validators = {
  register: [username, email, passwordRules, body('confirmPassword').optional().isString().isLength({ min: 8, max: 128 })],
  login: [body('username').isString().trim().isLength({ min: 1, max: 254 }), body('password').isString().isLength({ min: 1, max: 128 })],
  mfaVerify: [code],
  mfaLogin: [
    body('tempToken').isString().isLength({ min: 20, max: 600 }),
    body('code').isString().matches(/^(\d{6}|[A-Z0-9]{8})$/i)
  ],
  resetRequest: [email],
  resetConfirm: [token, passwordRules],
  changePassword: [body('currentPassword').isString().isLength({ min: 1, max: 128 }), passwordRules],
  aiAsk: [
    body('question').isString().trim().isLength({ min: 2, max: 2000 }),
    body('history').optional().isArray({ max: 8 })
  ],
  demoScenario: [
    body('scenario').isIn(['brute_force', 'privilege_escalation', 'buffer_overflow', 'trapdoor_scan', 'token_replay'])
  ],
  emailOtpSend: [
    body('purpose').optional().isString().isLength({ min: 2, max: 64 })
  ],
  emailOtpVerify: [
    body('otp').isString().matches(/^\d{6}$/),
    body('purpose').optional().isString().isLength({ min: 2, max: 64 })
  ],
  trustDevice: [
    body('sessionId').isString().isLength({ min: 8, max: 64 }),
    body('label').optional().isString().trim().isLength({ max: 64 })
  ],
  policyUpdate: [
    body('requireMfaForAdmins').optional().isBoolean(),
    body('lockoutThreshold').optional().isInt({ min: 3, max: 10 }),
    body('sessionMaxHours').optional().isInt({ min: 1, max: 720 }),
    body('staleSessionHours').optional().isInt({ min: 1, max: 720 }),
    body('emailOtpTtlMinutes').optional().isInt({ min: 2, max: 30 }),
    body('riskAlertThreshold').optional().isInt({ min: 40, max: 95 })
  ],
  incidentExplain: [
    body('incidentId').isInt({ min: 1 }).toInt()
  ],
  sessionId: [idParam],
  userId: [intIdParam],
  role: [intIdParam, body('role').isIn(['user', 'admin'])],
  pagination: [query('page').optional().isInt({ min: 1 }).toInt(), query('limit').optional().isInt({ min: 1, max: 100 }).toInt()],
  search: [query('search').optional().isString().trim().isLength({ max: 64 })],
  auditFilters: [query('event_type').optional().isString().isLength({ max: 64 }), query('user_id').optional().isInt({ min: 1 }).toInt()]
};

module.exports = { validators, passwordRules };
