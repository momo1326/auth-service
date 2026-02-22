const express = require('express');
const authMiddleware = require('../middleware/auth');
const controller = require('../controllers/applicationController');

const router = express.Router();
router.use(authMiddleware);

router.get('/dashboard', controller.dashboard);
router.get('/applications', controller.list);
router.post('/applications', controller.create);
router.patch('/applications/:id', controller.update);
router.delete('/applications/:id', controller.remove);

module.exports = router;
