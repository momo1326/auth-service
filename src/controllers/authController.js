const authService = require('../services/authService');
const db = require('../models/db');

async function signup(req, res, next) {
  try {
    return res.status(201).json(await authService.signup(req.body || {}));
  } catch (err) {
    return next(err);
  }
}

async function login(req, res, next) {
  try {
    return res.json(await authService.login({ ...(req.body || {}), ip: req.ip }));
  } catch (err) {
    return next(err);
  }
}

async function refresh(req, res, next) {
  try {
    return res.json(await authService.rotateRefreshToken(req.body?.refreshToken));
  } catch (err) {
    return next(err);
  }
}

async function verifyEmail(req, res, next) {
  try {
    await authService.verifyEmail(req.body?.token);
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

async function requestReset(req, res, next) {
  try {
    await authService.requestPasswordReset(req.body?.email);
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

async function resetPassword(req, res, next) {
  try {
    await authService.resetPassword({ token: req.body?.token, newPassword: req.body?.newPassword });
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

async function me(req, res, next) {
  try {
    const user = await db.get('SELECT id, email, role, is_verified, created_at FROM users WHERE id = ?', [req.user.userId]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user });
  } catch (err) {
    return next(err);
  }
}

module.exports = { signup, login, refresh, verifyEmail, requestReset, resetPassword, me };
