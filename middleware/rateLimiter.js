const rateLimit = require('express-rate-limit');

function makeLimiter(windowMs, max) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
      const reset = req.rateLimit && req.rateLimit.resetTime ? Math.ceil((req.rateLimit.resetTime.getTime() - Date.now()) / 1000) : Math.ceil(windowMs / 1000);
      res.set('Retry-After', String(Math.max(reset, 1)));
      res.status(options.statusCode).json({ error: 'Too many requests', code: 'RATE_LIMITED' });
    }
  });
}

module.exports = {
  generalLimiter: makeLimiter(15 * 60 * 1000, 100),
  loginLimiter: makeLimiter(15 * 60 * 1000, 10),
  registerLimiter: makeLimiter(60 * 60 * 1000, 5),
  passwordResetLimiter: makeLimiter(60 * 60 * 1000, 3)
};
