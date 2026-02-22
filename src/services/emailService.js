const logger = require('../utils/logger');

async function sendEmail({ to, subject, body }) {
  logger.info('Email simulated', { to, subject, body });
}

module.exports = { sendEmail };
