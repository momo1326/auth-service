const jwt = require('jsonwebtoken');

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

if (!ACCESS_TOKEN_SECRET) {
  console.warn('ACCESS_TOKEN_SECRET not set. Set it in .env');
}

function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'No authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: 'Invalid authorization header format' });
  }
  const token = parts[1];
  jwt.verify(token, ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] }, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = { id: payload.userId, email: payload.email };
    next();
  });
}

module.exports = authMiddleware;