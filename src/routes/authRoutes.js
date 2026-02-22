const express = require('express');
const controller = require('../controllers/authController');
const authMiddleware = require('../middleware/auth');
const { rateLimit } = require('../middleware/rateLimit');

const router = express.Router();

router.post('/signup', rateLimit({ keyPrefix: 'signup', windowMs: 15 * 60 * 1000, limit: 20 }), controller.signup);
router.post('/login', rateLimit({ keyPrefix: 'login', windowMs: 15 * 60 * 1000, limit: 30 }), controller.login);
router.post('/refresh', controller.refresh);
router.post('/verify-email', controller.verifyEmail);
router.post('/password-reset/request', rateLimit({ keyPrefix: 'pwd-reset', windowMs: 15 * 60 * 1000, limit: 10 }), controller.requestReset);
router.post('/password-reset/confirm', controller.resetPassword);
router.get('/me', authMiddleware, controller.me);

module.exports = router;
