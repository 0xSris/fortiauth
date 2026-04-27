const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { run } = require('../db/database');
const { sha256 } = require('../utils/crypto');
const { getPolicy } = require('./policyService');

function generateOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

async function sendMail(to, subject, text) {
  if (!smtpConfigured()) return { sent: false, reason: 'SMTP_NOT_CONFIGURED' };
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  await transporter.sendMail({
    from: process.env.SMTP_FROM || 'SecureOS <no-reply@secureos.local>',
    to,
    subject,
    text
  });
  return { sent: true };
}

async function createAndSendOtp(userId, purpose = 'email_verification', ttlMinutes) {
  const user = run((db) => db.prepare('SELECT id, email, username FROM users WHERE id = ?').get(userId), null);
  if (!user) {
    const error = new Error('User not found');
    error.code = 'USER_NOT_FOUND';
    throw error;
  }
  const otp = generateOtp();
  const ttl = Number(ttlMinutes || getPolicy().emailOtpTtlMinutes || 10);
  run((db) => db.prepare('INSERT INTO email_otps (user_id, otp_hash, purpose, expires_at) VALUES (?, ?, ?, unixepoch() + ?)').run(userId, sha256(otp), purpose, ttl * 60), null);
  const delivery = await sendMail(
    user.email,
    'Your SecureOS verification code',
    `Your SecureOS OTP is ${otp}. It expires in ${ttl} minutes. If you did not request this, ignore this email.`
  );
  return {
    sent: delivery.sent,
    reason: delivery.reason || null,
    expiresInMinutes: ttl,
    developmentOtp: process.env.NODE_ENV === 'production' || delivery.sent ? undefined : otp
  };
}

function verifyOtp(userId, otp, purpose = 'email_verification') {
  const row = run((db) => db.prepare('SELECT * FROM email_otps WHERE user_id = ? AND purpose = ? AND used = 0 AND expires_at > unixepoch() ORDER BY created_at DESC LIMIT 1').get(userId, purpose), null);
  if (!row || row.otp_hash !== sha256(otp)) return false;
  run((db) => db.prepare('UPDATE email_otps SET used = 1 WHERE id = ?').run(row.id), null);
  return true;
}

module.exports = { createAndSendOtp, verifyOtp, smtpConfigured };
