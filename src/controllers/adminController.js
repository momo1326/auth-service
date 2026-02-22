const db = require('../models/db');

async function users(req, res, next) {
  try {
    const rows = await db.all('SELECT id, email, role, is_verified, created_at FROM users ORDER BY created_at DESC');
    return res.json({ users: rows });
  } catch (err) {
    return next(err);
  }
}

module.exports = { users };
