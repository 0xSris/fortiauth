const helmet = require('helmet');
const cors = require('cors');

const defaultOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173'
];

function normalizeOrigin(origin) {
  return String(origin || '').trim().replace(/\/$/, '');
}

function configuredOrigins() {
  const explicit = String(process.env.CORS_ORIGINS || process.env.FRONTEND_URL || '')
    .split(',')
    .map(normalizeOrigin)
    .filter(Boolean);
  return new Set([...defaultOrigins, ...explicit]);
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  const normalized = normalizeOrigin(origin);
  if (configuredOrigins().has(normalized)) return true;
  try {
    const url = new URL(normalized);
    return url.protocol === 'https:' && url.hostname.endsWith('.vercel.app');
  } catch {
    return false;
  }
}

function securityMiddleware(app) {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:']
      }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
    frameguard: { action: 'deny' },
    noSniff: true,
    referrerPolicy: { policy: 'no-referrer' }
  }));
  app.use(cors({
    origin(origin, callback) {
      if (isAllowedOrigin(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));
}

module.exports = { securityMiddleware };
