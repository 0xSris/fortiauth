require('dotenv').config();

const readline = require('readline');
const { run } = require('./db/database');
const { hashPassword } = require('./services/passwordService');

if (!process.env.ADMIN_SEED_KEY) {
  process.stderr.write('Set ADMIN_SEED_KEY\n');
  process.exit(1);
}

function askPassword() {
  if (process.env.ADMIN_PASSWORD) return Promise.resolve(process.env.ADMIN_PASSWORD);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question('Admin password: ', (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

(async () => {
  const username = 'admin';
  const email = process.env.ADMIN_EMAIL || 'admin@example.com';
  const password = await askPassword();
  if (!password || password.length < 8) {
    process.stderr.write('Admin password must be at least 8 characters\n');
    process.exit(1);
  }
  const existing = run((db) => db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email), null);
  if (existing) {
    process.stdout.write(`Admin already exists: ${username} / ${email}\n`);
    process.exit(0);
  }
  const hash = await hashPassword(password);
  const result = run((db) => db.prepare('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)').run(username, email, hash, 'admin'), null);
  if (!result) {
    process.stderr.write('Unable to create admin user\n');
    process.exit(1);
  }
  process.stdout.write(`Admin user created.\nUsername: ${username}\nEmail: ${email}\nPassword: save the value you supplied; it will not be shown again.\n`);
})();
