const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const db = require('../db');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);
const DUMMY_PASSWORD_HASH = '$2b$10$z4h2Btllx4P4M5N3fQxq8OQdM4E46HoPazTA/gkGEXLJJLLq5yRvK'; // hash for "dummy-password"

if (!ACCESS_TOKEN_SECRET || !REFRESH_TOKEN_SECRET) {
  console.warn('ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET should be set in .env');
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 72) return false;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSymbol = /[^A-Za-z0-9]/.test(password);
  return hasUpper && hasLower && hasNumber && hasSymbol;
}

async function createAccessToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email },
    ACCESS_TOKEN_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
  );
}

async function createRefreshToken(user, options = {}) {
  const sessionId = uuidv4();
  const refreshToken = jwt.sign(
    { userId: user.id, sessionId },
    REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
  );

  const now = Math.floor(Date.now() / 1000);
  const decoded = jwt.decode(refreshToken);
  const expiresAt = decoded.exp || (now + 7 * 24 * 60 * 60);

  const tokenHash = await bcrypt.hash(refreshToken, BCRYPT_SALT_ROUNDS);

  await db.run(
    `INSERT INTO refresh_tokens (session_id, token_hash, user_id, expires_at, revoked, refresh_count, last_refresh_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [sessionId, tokenHash, user.id, expiresAt, false, options.refreshCount || 0, options.lastRefreshAt || null]
  );

  return refreshToken;
}

router.post('/signup', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const { password } = req.body || {};

    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (!isStrongPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8-72 chars and include upper/lowercase letters, number, and symbol' });
    }

    const existing = await db.get(`SELECT id FROM users WHERE email = ?`, [email]);
    if (existing) return res.status(409).json({ error: 'User already exists' });

    const hashed = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    const result = await db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashed]);
    const userId = result.lastID;

    const user = { id: userId, email };

    const accessToken = await createAccessToken(user);
    const refreshToken = await createRefreshToken(user);

    res.status(201).json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const { password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const ip = req.ip;
    const now = Math.floor(Date.now() / 1000);

    const attempt = await db.get(`SELECT * FROM login_attempts WHERE email = ? AND ip_address = ?`, [email, ip]);
    if (attempt && attempt.locked_until && attempt.locked_until > now) {
      return res.status(429).json({ error: 'Too many failed attempts, try again later' });
    }

    const user = await db.get(`SELECT id, email, password FROM users WHERE email = ?`, [email]);
    const passwordHash = user ? user.password : DUMMY_PASSWORD_HASH;
    const ok = await bcrypt.compare(password, passwordHash);

    if (!user || !ok) {
      if (!attempt) {
        await db.run(`INSERT INTO login_attempts (email, ip_address, failed_attempts, locked_until, updated_at) VALUES (?, ?, 1, NULL, ?)`, [email, ip, now]);
      } else {
        const newAttempts = attempt.failed_attempts + 1;
        const locked = newAttempts >= 5 ? now + 15 * 60 : null;
        await db.run(`UPDATE login_attempts SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE email = ? AND ip_address = ?`, [newAttempts, locked, now, email, ip]);
      }
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await db.run(`DELETE FROM login_attempts WHERE email = ? AND ip_address = ?`, [email, ip]);

    const accessToken = await createAccessToken(user);
    const refreshToken = await createRefreshToken(user);

    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, { algorithms: ['HS256'] }, async (err, payload) => {
      if (err) return res.status(401).json({ error: 'Invalid or expired refresh token' });

      try {
        const { userId, sessionId } = payload;

        const row = await db.get(`SELECT * FROM refresh_tokens WHERE session_id = ?`, [sessionId]);
        if (!row) return res.status(401).json({ error: 'Refresh token revoked' });

        const isValidToken = await bcrypt.compare(refreshToken, row.token_hash);
        if (!isValidToken) return res.status(401).json({ error: 'Invalid refresh token' });

        const now = Math.floor(Date.now() / 1000);
        const oneHourAgo = now - 3600;

        let refreshCount = row.refresh_count || 0;
        if (row.last_refresh_at && row.last_refresh_at < oneHourAgo) {
          refreshCount = 0;
        }

        if (refreshCount >= 10) {
          await db.run(`UPDATE refresh_tokens SET revoked = TRUE WHERE session_id = ?`, [sessionId]);
          return res.status(429).json({ error: 'Too many refresh attempts, session revoked' });
        }

        if (row.expires_at < now) {
          await db.run(`UPDATE refresh_tokens SET revoked = TRUE WHERE session_id = ?`, [sessionId]);
          return res.status(401).json({ error: 'Refresh token expired' });
        }

        const revokeResult = await db.run(
          `UPDATE refresh_tokens SET revoked = TRUE WHERE session_id = ? AND revoked = FALSE`,
          [sessionId]
        );
        if (revokeResult.changes === 0) {
          console.warn(`Security incident: Refresh token replay detected for user ${userId}, logging out all sessions`);
          await db.run(`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ?`, [userId]);
          return res.status(401).json({ error: 'Refresh token suspected compromise - all sessions logged out' });
        }

        const user = await db.get(`SELECT id, email FROM users WHERE id = ?`, [userId]);
        if (!user) return res.status(401).json({ error: 'User not found' });

        const accessToken = await createAccessToken(user);
        const newRefreshToken = await createRefreshToken(user, {
          refreshCount: refreshCount + 1,
          lastRefreshAt: now,
        });

        res.json({ accessToken, refreshToken: newRefreshToken });
      } catch (callbackErr) {
        console.error(callbackErr);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, { ignoreExpiration: true, algorithms: ['HS256'] }, async (err, payload) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid refresh token' });
      }

      try {
        const { sessionId } = payload;
        const row = await db.get(`SELECT * FROM refresh_tokens WHERE session_id = ?`, [sessionId]);
        if (!row) return res.status(204).send();

        const isValidToken = await bcrypt.compare(refreshToken, row.token_hash);
        if (!isValidToken) return res.status(400).json({ error: 'Invalid refresh token' });

        await db.run(`UPDATE refresh_tokens SET revoked = TRUE WHERE session_id = ?`, [sessionId]);
        res.status(204).send();
      } catch (callbackErr) {
        console.error(callbackErr);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


router.get('/sessions', authMiddleware, async (req, res) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const sessions = await db.all(
      `SELECT session_id, expires_at, refresh_count, last_refresh_at, created_at FROM refresh_tokens WHERE user_id = ? AND revoked = FALSE AND expires_at > ? ORDER BY created_at DESC`,
      [req.user.id, now]
    );

    res.json({ sessions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/logout-all', authMiddleware, async (req, res) => {
  try {
    await db.run(`UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ?`, [req.user.id]);
    res.status(204).send();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await db.get(`SELECT id, email, created_at FROM users WHERE id = ?`, [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
