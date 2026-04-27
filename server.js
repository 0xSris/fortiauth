require('dotenv').config();

const path = require('path');
const express = require('express');
const { securityMiddleware } = require('./middleware/security');
const { generalLimiter } = require('./middleware/rateLimiter');
const { detectPrivilegeEscalation } = require('./middleware/sanitize');
const { logger } = require('./utils/logger');
const { dbPath } = require('./db/database');

const app = express();
const port = Number(process.env.PORT || 3000);

app.set('trust proxy', 1);
securityMiddleware(app);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.get('/health', (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'secureos-auth-framework',
    env: process.env.NODE_ENV || 'development',
    uptime: Math.round(process.uptime())
  });
});
app.use((req, res, next) => {
  req.cookies = String(req.headers.cookie || '').split(';').filter(Boolean).reduce((acc, part) => {
    const index = part.indexOf('=');
    if (index > -1) acc[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    return acc;
  }, {});
  next();
});
app.use('/api', generalLimiter, detectPrivilegeEscalation);

app.use('/api/auth', require('./routes/auth'));
app.use('/api/user', require('./routes/user'));
app.use('/api/ai', require('./routes/ai'));
app.use('/api/admin', require('./routes/admin'));

app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found', code: 'NOT_FOUND' }));
app.use((error, req, res, next) => {
  logger.error('Unhandled request error', error);
  res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR' });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(port, () => {
  logger.info([
    'SecureOS Authentication Framework',
    `Port: ${port}`,
    `Env: ${process.env.NODE_ENV || 'development'}`,
    `DB: ${dbPath}`,
    `JWT expiry: ${process.env.JWT_EXPIRES_IN || '15m'}`
  ].join('\n'));
});
