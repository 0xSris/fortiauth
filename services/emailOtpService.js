const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { run } = require('../db/database');
const { sha256 } = require('../utils/crypto');
const { getPolicy } = require('./policyService');
const { logger } = require('../utils/logger');

let transporter;

function generateOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function getTransporter() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || 'false') === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT_MS || 4000),
      greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT_MS || 4000),
      socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT_MS || 6000)
    });
  }
  return transporter;
}

async function sendMail(to, subject, text) {
  if (!smtpConfigured()) return { sent: false, reason: 'SMTP_NOT_CONFIGURED' };
  await getTransporter().sendMail({
    from: process.env.SMTP_FROM || 'SecureOS <no-reply@secureos.local>',
    to,
    subject,
    text
  });
  return { sent: true };
}

async function createAndSendOtp(userId, purpose = 'email_verification', ttlMinutes, options = {}) {
  const user = run((db) => db.prepare('SELECT id, email, username FROM users WHERE id = ?').get(userId), null);
  if (!user) {
    const error = new Error('User not found');
    error.code = 'USER_NOT_FOUND';
    throw error;
  }
  const otp = generateOtp();
  const ttl = Number(ttlMinutes || getPolicy().emailOtpTtlMinutes || 10);
  run((db) => db.prepare('INSERT INTO email_otps (user_id, otp_hash, purpose, expires_at) VALUES (?, ?, ?, unixepoch() + ?)').run(userId, sha256(otp), purpose, ttl * 60), null);
  const message = [
    user.email,
    'Your SecureOS verification code',
    `Your SecureOS OTP is ${otp}. It expires in ${ttl} minutes. If you did not request this, ignore this email.`
  ];
  if (options.asyncDelivery && smtpConfigured()) {
    sendMail(...message).catch((error) => logger.error('Email OTP delivery failed', error));
    return {
      sent: true,
      queued: true,
      reason: null,
      expiresInMinutes: ttl
    };
  }
  const delivery = await sendMail(...message);
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
