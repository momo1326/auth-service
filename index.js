require('dotenv').config();

const express = require('express');
const path = require('path');

const db = require('./src/models/db');
const authRoutes = require('./src/routes/authRoutes');
const appRoutes = require('./src/routes/applicationRoutes');
const adminRoutes = require('./src/routes/adminRoutes');
const { errorHandler } = require('./src/middleware/errorHandler');
const logger = require('./src/utils/logger');

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

app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/auth', authRoutes);
app.use('/api', appRoutes);
app.use('/api/admin', adminRoutes);
app.get('/health', (req, res) => res.json({ ok: true }));

app.use(errorHandler);

const PORT = process.env.PORT || 3000;

(async () => {
  await db.init();
  app.listen(PORT, () => logger.info('job-tracker-api listening', { port: PORT }));
})();
