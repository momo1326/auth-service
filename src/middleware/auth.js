const jwt = require('jsonwebtoken');

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Authorization header required' });

  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Invalid authorization header' });

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired access token' });
    req.user = payload;
    next();
  });
}

module.exports = authMiddleware;
