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
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10');

if (!ACCESS_TOKEN_SECRET || !REFRESH_TOKEN_SECRET) {
  console.warn('ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET should be set in .env');
}

async function createAccessToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email },
    ACCESS_TOKEN_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
  );
}

async function createRefreshToken(user) {
  const tokenId = uuidv4();
  const refreshToken = jwt.sign(
    { userId: user.id, tokenId },
    REFRESH_TOKEN_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
  );

  // calculate expiry timestamp in seconds
  const now = Math.floor(Date.now() / 1000);
  let expiresInSec = 7 * 24 * 60 * 60; // default 7d
  // For reliability, set expiresAt from JWT payload
  const decoded = jwt.decode(refreshToken);
  const expiresAt = decoded.exp || (now + expiresInSec);

  await db.run(
    `INSERT INTO refresh_tokens (token_id, user_id, expires_at) VALUES (?, ?, ?)`,
    [tokenId, user.id, expiresAt]
  );

  return refreshToken;
}

router.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

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
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const user = await db.get(`SELECT id, email, password FROM users WHERE email = ?`, [email]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

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
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, async (err, payload) => {
      if (err) return res.status(401).json({ error: 'Invalid or expired refresh token' });
      const { userId, tokenId } = payload;
      // lookup tokenId
      const row = await db.get(`SELECT * FROM refresh_tokens WHERE token_id = ?`, [tokenId]);
      if (!row) return res.status(401).json({ error: 'Refresh token revoked' });

      // optional: check expiry
      const now = Math.floor(Date.now() / 1000);
      if (row.expires_at < now) {
        // cleanup
        await db.run(`DELETE FROM refresh_tokens WHERE token_id = ?`, [tokenId]);
        return res.status(401).json({ error: 'Refresh token expired' });
      }

      // rotate: delete old record and issue new refresh token
      await db.run(`DELETE FROM refresh_tokens WHERE token_id = ?`, [tokenId]);

      const user = await db.get(`SELECT id, email FROM users WHERE id = ?`, [userId]);
      if (!user) return res.status(401).json({ error: 'User not found' });

      const accessToken = await createAccessToken(user);
      const newRefreshToken = await createRefreshToken(user);

      res.json({ accessToken, refreshToken: newRefreshToken });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' });

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, async (err, payload) => {
      if (err) {
        // If token invalid/expired, still respond 204 to avoid leaking state
        return res.status(204).send();
      }
      const { tokenId } = payload;
      await db.run(`DELETE FROM refresh_tokens WHERE token_id = ?`, [tokenId]);
      res.status(204).send();
    });
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