require('dotenv').config();

const express = require('express');

const db = require('./db');
const authRoutes = require('./routes/auth');

const app = express();

const requiredSecrets = ['ACCESS_TOKEN_SECRET', 'REFRESH_TOKEN_SECRET'];
const missingSecrets = requiredSecrets.filter((k) => !process.env[k]);
if (missingSecrets.length) {
  console.error(`Missing required env vars: ${missingSecrets.join(', ')}`);
  process.exit(1);
}

const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
app.set('trust proxy', TRUST_PROXY);
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// initialize DB (creates tables if needed)
app.use('/', authRoutes);

app.get('/', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;

async function start() {
  await db.init();
  app.listen(PORT, () => {
    console.log(`auth-service listening on http://localhost:${PORT}`);
  });
}

start().catch((err) => {
  console.error('Failed to initialize service', err);
  process.exit(1);
});
