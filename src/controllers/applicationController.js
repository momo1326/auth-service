const appService = require('../services/applicationService');

async function create(req, res, next) {
  try {
    return res.status(201).json({ application: await appService.createApplication(req.user.userId, req.body || {}) });
  } catch (err) {
    return next(err);
  }
}

async function list(req, res, next) {
  try {
    return res.json(await appService.listApplications(req.user.userId, req.query));
  } catch (err) {
    return next(err);
  }
}

async function update(req, res, next) {
  try {
    return res.json({ application: await appService.updateApplication(req.user.userId, req.params.id, req.body || {}) });
  } catch (err) {
    return next(err);
  }
}

async function remove(req, res, next) {
  try {
    await appService.deleteApplication(req.user.userId, req.params.id);
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

async function dashboard(req, res, next) {
  try {
    return res.json(await appService.getDashboard(req.user.userId));
  } catch (err) {
    return next(err);
  }
}

module.exports = { create, list, update, remove, dashboard };
