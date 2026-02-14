require('dotenv').config();

const express = require('express');

const db = require('./db');
const authRoutes = require('./routes/auth');

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// initialize DB (creates tables if needed)
db.init();

app.use('/', authRoutes);

app.get('/', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`auth-service listening on http://localhost:${PORT}`);
});
