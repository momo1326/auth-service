require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');

const db = require('./db');
const authRoutes = require('./routes/auth');

const app = express();
app.set('trust proxy', 1);
app.use(bodyParser.json());

// initialize DB (creates tables if needed)
db.init();

app.use('/', authRoutes);

app.get('/', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`auth-service listening on http://localhost:${PORT}`);
});