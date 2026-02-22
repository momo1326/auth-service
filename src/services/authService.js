const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const db = require('../models/db');
const { HttpError } = require('../utils/httpError');
const { normalizeEmail, isStrongPassword, isValidEmail } = require('../utils/password');
const { generateRandomToken, hashToken } = require('../utils/tokens');
const emailService = require('./emailService');

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 10);
const DUMMY_PASSWORD_HASH = '$2b$10$z4h2Btllx4P4M5N3fQxq8OQdM4E46HoPazTA/gkGEXLJJLLq5yRvK';

function createAccessToken(user) {
  return jwt.sign({ userId: user.id, email: user.email, role: user.role }, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}

async function createRefreshToken(user, refreshCount = 0) {
  const sessionId = uuidv4();
  const refreshToken = jwt.sign({ userId: user.id, sessionId }, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });
  const tokenHash = await bcrypt.hash(refreshToken, BCRYPT_SALT_ROUNDS);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = jwt.decode(refreshToken).exp || now + (7 * 24 * 3600);

  await db.run(
    'INSERT INTO refresh_tokens (session_id, token_hash, user_id, expires_at, revoked, refresh_count, last_refresh_at) VALUES (?, ?, ?, ?, 0, ?, ?)',
    [sessionId, tokenHash, user.id, expiresAt, refreshCount, now],
  );

  return refreshToken;
}

async function signup({ email, password, role = 'user' }) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail || !password) throw new HttpError(400, 'email and password required');
  if (!isValidEmail(normalizedEmail)) throw new HttpError(400, 'Invalid email format');
  if (!isStrongPassword(password)) throw new HttpError(400, 'Password must be strong');
  if (!['user', 'admin'].includes(role)) throw new HttpError(400, 'Invalid role');

  const existing = await db.get('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
  if (existing) throw new HttpError(409, 'User already exists');

  const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
  const result = await db.run('INSERT INTO users (email, password, role, is_verified) VALUES (?, ?, ?, 0)', [normalizedEmail, hashedPassword, role]);
  const user = { id: result.lastID, email: normalizedEmail, role };

  const rawToken = generateRandomToken();
  await db.run('INSERT INTO email_verification_tokens (user_id, token_hash, expires_at, used) VALUES (?, ?, ?, 0)', [user.id, hashToken(rawToken), Math.floor(Date.now() / 1000) + 24 * 3600]);
  await emailService.sendEmail({ to: normalizedEmail, subject: 'Verify your account', body: `Verification token: ${rawToken}` });

  return { user, accessToken: createAccessToken(user), refreshToken: await createRefreshToken(user) };
}

async function login({ email, password, ip }) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail || !password) throw new HttpError(400, 'email and password required');

  const now = Math.floor(Date.now() / 1000);
  const attempt = await db.get('SELECT * FROM login_attempts WHERE email = ? AND ip_address = ?', [normalizedEmail, ip]);
  if (attempt && attempt.locked_until && attempt.locked_until > now) throw new HttpError(429, 'Too many failed attempts, try later');

  const user = await db.get('SELECT id, email, password, role, is_verified FROM users WHERE email = ?', [normalizedEmail]);
  const passwordHash = user ? user.password : DUMMY_PASSWORD_HASH;
  const valid = await bcrypt.compare(password, passwordHash);

  if (!user || !valid) {
    if (!attempt) await db.run('INSERT INTO login_attempts (email, ip_address, failed_attempts, updated_at) VALUES (?, ?, 1, ?)', [normalizedEmail, ip, now]);
    else await db.run('UPDATE login_attempts SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?', [attempt.failed_attempts + 1, attempt.failed_attempts + 1 >= 5 ? now + 900 : null, now, attempt.id]);
    throw new HttpError(401, 'Invalid credentials');
  }

  await db.run('DELETE FROM login_attempts WHERE email = ? AND ip_address = ?', [normalizedEmail, ip]);
  return { user, accessToken: createAccessToken(user), refreshToken: await createRefreshToken(user) };
}

async function rotateRefreshToken(refreshToken) {
  if (!refreshToken) throw new HttpError(400, 'refreshToken required');

  const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
  const row = await db.get('SELECT * FROM refresh_tokens WHERE session_id = ?', [payload.sessionId]);
  if (!row || row.revoked) throw new HttpError(401, 'Refresh token revoked');

  const valid = await bcrypt.compare(refreshToken, row.token_hash);
  if (!valid) throw new HttpError(401, 'Invalid refresh token');

  const now = Math.floor(Date.now() / 1000);
  const currentCount = row.last_refresh_at && row.last_refresh_at < now - 3600 ? 0 : row.refresh_count;
  if (currentCount >= 10) {
    await db.run('UPDATE refresh_tokens SET revoked = 1 WHERE session_id = ?', [payload.sessionId]);
    throw new HttpError(429, 'Too many refresh attempts');
  }

  await db.run('UPDATE refresh_tokens SET revoked = 1 WHERE session_id = ?', [payload.sessionId]);
  const user = await db.get('SELECT id, email, role FROM users WHERE id = ?', [payload.userId]);
  if (!user) throw new HttpError(404, 'User not found');

  return { accessToken: createAccessToken(user), refreshToken: await createRefreshToken(user, currentCount + 1) };
}

async function verifyEmail(token) {
  if (!token) throw new HttpError(400, 'Verification token required');
  const hashed = hashToken(token);
  const row = await db.get('SELECT * FROM email_verification_tokens WHERE token_hash = ? AND used = 0', [hashed]);
  if (!row || row.expires_at < Math.floor(Date.now() / 1000)) throw new HttpError(400, 'Invalid or expired verification token');
  await db.run('UPDATE users SET is_verified = 1 WHERE id = ?', [row.user_id]);
  await db.run('UPDATE email_verification_tokens SET used = 1 WHERE id = ?', [row.id]);
}

async function requestPasswordReset(email) {
  const user = await db.get('SELECT id, email FROM users WHERE email = ?', [normalizeEmail(email)]);
  if (!user) return;
  const rawToken = generateRandomToken();
  await db.run('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used) VALUES (?, ?, ?, 0)', [user.id, hashToken(rawToken), Math.floor(Date.now() / 1000) + 3600]);
  await emailService.sendEmail({ to: user.email, subject: 'Password reset', body: `Password reset token: ${rawToken}` });
}

async function resetPassword({ token, newPassword }) {
  if (!isStrongPassword(newPassword)) throw new HttpError(400, 'New password is not strong enough');
  const row = await db.get('SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used = 0', [hashToken(token)]);
  if (!row || row.expires_at < Math.floor(Date.now() / 1000)) throw new HttpError(400, 'Invalid or expired reset token');
  await db.run('UPDATE users SET password = ? WHERE id = ?', [await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS), row.user_id]);
  await db.run('UPDATE password_reset_tokens SET used = 1 WHERE id = ?', [row.id]);
  await db.run('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?', [row.user_id]);
}

module.exports = { signup, login, rotateRefreshToken, verifyEmail, requestPasswordReset, resetPassword };
