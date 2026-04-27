# SecureOS Authentication Security Framework

SecureOS is a complete Express, SQLite, JWT, refresh-token, TOTP MFA authentication framework with a React single-page security console.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create `.env` from `.env.example` and replace every secret.
3. Seed the first administrator:
   ```bash
   ADMIN_SEED_KEY=your_seed_key ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='StrongPass!123' npm run seed
   ```
4. Start the app:
   ```bash
   npm run build
   npm start
   ```
5. Open `http://localhost:3000`.

For frontend development, run the API with `npm start` and the React dev server with:
   ```bash
   npm run client:dev
   ```

The SQLite file is created automatically on first run. The schema is loaded from `db/schema.sql`.

## Environment

| Variable | Required | Description |
| --- | --- | --- |
| `PORT` | Yes | HTTP port, default `3000`. |
| `NODE_ENV` | Yes | `development`, `production`, or `test`. |
| `DATABASE_PATH` | Yes | SQLite database path. |
| `JWT_SECRET` | Yes | Secret used to sign access and temporary MFA JWTs. Use at least 64 random characters. |
| `JWT_EXPIRES_IN` | Yes | Access token lifetime, default `15m`. |
| `REFRESH_TOKEN_EXPIRES_DAYS` | Yes | Refresh token lifetime in days, default `7`. |
| `MFA_ENCRYPTION_KEY` | Yes | MFA AES-256-GCM secret. A 32-character string is used directly; other values are SHA-256 derived. |
| `ADMIN_SEED_KEY` | Yes for seed | Guard value required before `seed.js` runs. |
| `FRONTEND_URL` | Yes | CORS origin for the SPA. |
| `CORS_ORIGINS` | No | Comma-separated allowed origins. Localhost and `https://*.vercel.app` are allowed automatically. |
| `REFRESH_COOKIE_SAMESITE` | No | Refresh cookie SameSite value. Use `none` for Vercel-to-Render cross-site deployment. |
| `REFRESH_COOKIE_SECURE` | No | Set to `true` in production so refresh cookies are HTTPS-only. |
| `ADMIN_EMAIL` | No | Seed admin email. |
| `ADMIN_PASSWORD` | No | Seed admin password; prompted if omitted. |
| `GROQ_API_KEY` | No | Enables the AI assistant. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | Production login | Sends 2-minute email OTP login challenges. In development, the OTP is returned in the response when SMTP is not configured. |

## Production Deployment

This repository is configured for an Express API on Render and a Vite React frontend on Vercel.

### Render API

1. Push the repository to GitHub.
2. In Render, create a new Blueprint from the repo. Render will read `render.yaml`.
3. Set these environment variables in Render:
   ```text
   FRONTEND_URL=https://your-secureos-frontend.vercel.app
   CORS_ORIGINS=https://your-secureos-frontend.vercel.app,https://*.vercel.app,http://localhost:3000,http://localhost:5173
   GROQ_API_KEY=your_groq_key
   SMTP_HOST=your_smtp_host
   SMTP_USER=your_smtp_user
   SMTP_PASS=your_smtp_password
   SMTP_FROM=SecureOS <no-reply@your-domain.com>
   ```
4. Keep `REFRESH_COOKIE_SAMESITE=none` and `REFRESH_COOKIE_SECURE=true` for the Vercel-to-Render split.
5. Render health checks use:
   ```text
   GET /health
   ```

The Render start command uses `node --max-old-space-size=256 server.js` and `UV_THREADPOOL_SIZE=2` for free-instance memory safety. The backend install command is `npm ci --omit=dev`, so production does not install development-only packages.

Production login sends an email OTP after the password is accepted. The code expires in 2 minutes. Configure SMTP before presenting the deployed app, otherwise the API will reject login with `EMAIL_OTP_NOT_CONFIGURED`.

SQLite on the free Render plan uses `/tmp/secureos-auth.db`, which is ephemeral. For persistent production data, attach a Render disk or replace SQLite with a managed database.

### Vercel Frontend

1. Import the same repository into Vercel.
2. Keep the project root as the Vercel root. Vercel will read `vercel.json`.
3. Add this frontend environment variable:
   ```text
   VITE_API_BASE_URL=https://your-secureos-api.onrender.com
   ```
4. Deploy. The build command is `npm run build`, and the static output directory is `public`.

For local development, leave `VITE_API_BASE_URL` unset. The frontend will call local `/api` routes through Vite's proxy.

Production examples are included in `.env.production.example` and `client/.env.production.example`.

## Security Notes

Passwords use Argon2id with memory cost `65536`, time cost `3`, and parallelism `4`. Refresh tokens are generated with Node `crypto`, stored only as SHA-256 hashes, rotated on every refresh, and delivered as `httpOnly`, `SameSite=Strict` cookies. MFA secrets are encrypted at rest with AES-256-GCM. JWT payloads contain only `userId` and `sessionId`; admin role checks fetch the role fresh from SQLite.

All request bodies are capped at `10kb`. Validation is enforced with `express-validator` before business logic. API errors use `{ "error": "message", "code": "CODE" }`.

## API Endpoints

| Method | Path | Auth | Body | Response |
| --- | --- | --- | --- | --- |
| `GET` | `/health` | No | none | `{ ok, service, env, uptime }` |
| `POST` | `/api/auth/register` | No | `{ username, email, password, confirmPassword? }` | `{ id, username, email }` |
| `POST` | `/api/auth/login` | No | `{ username, password }` | `{ requiresEmailOtp, tempToken, email, expiresInMinutes }` |
| `POST` | `/api/auth/email-otp/login` | Email temp token | `{ tempToken, otp }` | `{ accessToken, user, sessionId }` or `{ requiresMfa, tempToken }` |
| `POST` | `/api/auth/logout` | User | none | `{ ok }` |
| `POST` | `/api/auth/refresh` | Refresh cookie | none | `{ accessToken, sessionId }` |
| `POST` | `/api/auth/mfa/setup` | User | none | `{ secret, qrCodeDataUrl, backupCodes }` |
| `POST` | `/api/auth/mfa/verify` | User | `{ code }` | `{ ok }` |
| `POST` | `/api/auth/mfa/login` | Temp token | `{ tempToken, code }` | `{ accessToken, user, sessionId }` |
| `POST` | `/api/auth/mfa/disable` | User | `{ code }` | `{ ok }` |
| `POST` | `/api/auth/mfa/backup-codes/rotate` | User | `{ code }` | `{ backupCodes }` |
| `POST` | `/api/auth/password-reset/request` | No | `{ email }` | `{ ok }`; development also returns `{ resetToken }` |
| `POST` | `/api/auth/password-reset/confirm` | No | `{ token, password }` | `{ ok }` |
| `GET` | `/api/user/me` | User | none | `{ user }` |
| `GET` | `/api/user/security-overview` | User | none | `{ overview }` |
| `POST` | `/api/user/ai/ask` | User | `{ question }` | `{ answer, model, usage }` |
| `GET` | `/api/user/demo/showcase` | User | none | `{ scenarios, talkingPoints }` |
| `POST` | `/api/user/demo/simulate` | User | `{ scenario }` | `{ simulation }` |
| `GET` | `/api/user/security-report` | User | none | `{ report }` |
| `PUT` | `/api/user/me/password` | User | `{ currentPassword, password }` | `{ ok }` |
| `GET` | `/api/user/sessions` | User | none | `{ sessions, currentSessionId }` |
| `DELETE` | `/api/user/sessions/:id` | User | none | `{ ok }` |
| `GET` | `/api/admin/users` | Admin | query `{ page?, limit?, search? }` | `{ users, page, limit, total }` |
| `GET` | `/api/admin/users/:id` | Admin | none | `{ user }` |
| `PUT` | `/api/admin/users/:id/role` | Admin | `{ role: "user" | "admin" }` | `{ ok }` |
| `POST` | `/api/admin/users/:id/unlock` | Admin | none | `{ ok }` |
| `GET` | `/api/admin/audit-log` | Admin | query `{ page?, limit?, event_type?, user_id? }` | `{ events, page, limit }` |
| `GET` | `/api/admin/stats` | Admin | none | `{ stats }` |
| `GET` | `/api/admin/security-posture` | Admin | none | `{ stats }` |

## Frontend Routes

The Express server serves the compiled React SPA shell for `/login`, `/register`, `/forgot`, `/reset`, `/dashboard`, `/admin`, and any other non-API route.
