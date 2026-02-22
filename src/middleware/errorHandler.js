const { HttpError } = require('../utils/httpError');
const logger = require('../utils/logger');

function errorHandler(err, req, res, next) {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.message });
  }

  logger.error('Unhandled error', { message: err.message, stack: err.stack, path: req.path });
  return res.status(500).json({ error: 'Internal server error' });
}

module.exports = { errorHandler };
