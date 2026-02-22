const express = require('express');
const authMiddleware = require('../middleware/auth');
const { requireRole } = require('../middleware/role');
const controller = require('../controllers/adminController');

const router = express.Router();
router.use(authMiddleware, requireRole('admin'));
router.get('/users', controller.users);

module.exports = router;
