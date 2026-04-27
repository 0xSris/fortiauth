const argon2 = require('argon2');
const { commonPasswords } = require('../utils/commonPasswords');

const options = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4
};

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) return 'Password must be 8 to 128 characters';
  if (commonPasswords.has(password.toLowerCase())) return 'Password is too common';
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return 'Password must include uppercase, lowercase, digit, and special character';
  }
  return null;
}

async function hashPassword(password) {
  return argon2.hash(password, options);
}

async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

module.exports = { hashPassword, verifyPassword, validatePassword, options };
