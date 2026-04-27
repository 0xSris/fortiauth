const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { run } = require('../db/database');
const { encrypt, decrypt, backupCode } = require('../utils/crypto');
const { hashPassword, verifyPassword } = require('./passwordService');

authenticator.options = { step: 30, window: 1, digits: 6 };

async function setupMfa(user) {
  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(user.email, 'SecureOS', secret);
  const qrCodeDataUrl = await QRCode.toDataURL(otpauth);
  const backupCodes = Array.from({ length: 10 }, backupCode);
  const hashedCodes = [];
  for (const code of backupCodes) hashedCodes.push(await hashPassword(code));
  const encryptedSecret = encrypt(secret);
  const saved = run((db) => {
    const existing = db.prepare('SELECT id FROM mfa_configs WHERE user_id = ?').get(user.id);
    if (existing) {
      db.prepare('UPDATE mfa_configs SET totp_secret = ?, is_enabled = 0, backup_codes = ? WHERE user_id = ?')
        .run(encryptedSecret, JSON.stringify(hashedCodes), user.id);
    } else {
      db.prepare('INSERT INTO mfa_configs (user_id, totp_secret, backup_codes) VALUES (?, ?, ?)')
        .run(user.id, encryptedSecret, JSON.stringify(hashedCodes));
    }
    return true;
  }, false);
  if (!saved) throw new Error('Unable to save MFA configuration');
  return { secret, qrCodeDataUrl, backupCodes };
}

async function rotateBackupCodes(userId) {
  const backupCodes = Array.from({ length: 10 }, backupCode);
  const hashedCodes = [];
  for (const code of backupCodes) hashedCodes.push(await hashPassword(code));
  const saved = run((db) => db.prepare('UPDATE mfa_configs SET backup_codes = ? WHERE user_id = ?').run(JSON.stringify(hashedCodes), userId), null);
  if (!saved || saved.changes === 0) throw new Error('Unable to rotate backup codes');
  return backupCodes;
}

function getMfaConfig(userId) {
  return run((db) => db.prepare('SELECT * FROM mfa_configs WHERE user_id = ?').get(userId), null);
}

function verifyTotp(config, code) {
  if (!config || !code) return false;
  return authenticator.check(String(code), decrypt(config.totp_secret));
}

async function verifyBackupCode(config, code) {
  if (!config || !config.backup_codes) return false;
  const hashes = JSON.parse(config.backup_codes);
  for (let i = 0; i < hashes.length; i += 1) {
    if (await verifyPassword(hashes[i], code)) {
      hashes.splice(i, 1);
      run((db) => db.prepare('UPDATE mfa_configs SET backup_codes = ? WHERE id = ?').run(JSON.stringify(hashes), config.id), null);
      return true;
    }
  }
  return false;
}

function enableMfa(userId) {
  return run((db) => db.prepare('UPDATE mfa_configs SET is_enabled = 1 WHERE user_id = ?').run(userId), null);
}

function disableMfa(userId) {
  return run((db) => db.prepare('UPDATE mfa_configs SET is_enabled = 0 WHERE user_id = ?').run(userId), null);
}

module.exports = { setupMfa, rotateBackupCodes, getMfaConfig, verifyTotp, verifyBackupCode, enableMfa, disableMfa };
