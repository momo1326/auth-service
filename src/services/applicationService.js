const db = require('../models/db');
const { HttpError } = require('../utils/httpError');

const STATUSES = ['Applied', 'Interview', 'Offer', 'Rejected'];

function normalizeStatus(status) {
  return STATUSES.includes(status) ? status : 'Applied';
}

async function createApplication(userId, payload) {
  const { company, roleTitle, status, appliedDate, location, salaryMin, salaryMax, notes } = payload;
  if (!company || !roleTitle) throw new HttpError(400, 'company and roleTitle are required');

  const result = await db.run(
    `INSERT INTO job_applications (user_id, company, role_title, status, applied_date, location, salary_min, salary_max, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, company, roleTitle, normalizeStatus(status), appliedDate || null, location || null, salaryMin || null, salaryMax || null, notes || null],
  );

  return db.get('SELECT * FROM job_applications WHERE id = ?', [result.lastID]);
}

async function listApplications(userId, query) {
  const page = Math.max(1, Number(query.page || 1));
  const pageSize = Math.min(50, Math.max(1, Number(query.pageSize || 10)));
  const offset = (page - 1) * pageSize;

  const filters = ['user_id = ?'];
  const params = [userId];

  if (query.status && STATUSES.includes(query.status)) {
    filters.push('status = ?');
    params.push(query.status);
  }

  if (query.search) {
    filters.push('(company LIKE ? OR role_title LIKE ?)');
    params.push(`%${query.search}%`, `%${query.search}%`);
  }

  const sortBy = ['created_at', 'company', 'status'].includes(query.sortBy) ? query.sortBy : 'created_at';
  const sortDir = query.sortDir === 'asc' ? 'ASC' : 'DESC';

  const where = filters.join(' AND ');

  const rows = await db.all(
    `SELECT * FROM job_applications WHERE ${where} ORDER BY ${sortBy} ${sortDir} LIMIT ? OFFSET ?`,
    [...params, pageSize, offset],
  );

  const countRow = await db.get(`SELECT COUNT(*) AS total FROM job_applications WHERE ${where}`, params);
  return {
    data: rows,
    pagination: { page, pageSize, total: countRow.total, totalPages: Math.ceil(countRow.total / pageSize) || 1 },
  };
}

async function updateApplication(userId, id, payload) {
  const existing = await db.get('SELECT * FROM job_applications WHERE id = ? AND user_id = ?', [id, userId]);
  if (!existing) throw new HttpError(404, 'Application not found');

  const next = {
    company: payload.company || existing.company,
    role_title: payload.roleTitle || existing.role_title,
    status: payload.status ? normalizeStatus(payload.status) : existing.status,
    applied_date: payload.appliedDate || existing.applied_date,
    location: payload.location || existing.location,
    salary_min: payload.salaryMin ?? existing.salary_min,
    salary_max: payload.salaryMax ?? existing.salary_max,
    notes: payload.notes ?? existing.notes,
  };

  await db.run(
    `UPDATE job_applications SET company = ?, role_title = ?, status = ?, applied_date = ?, location = ?, salary_min = ?, salary_max = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`,
    [next.company, next.role_title, next.status, next.applied_date, next.location, next.salary_min, next.salary_max, next.notes, id, userId],
  );

  return db.get('SELECT * FROM job_applications WHERE id = ?', [id]);
}

async function deleteApplication(userId, id) {
  const result = await db.run('DELETE FROM job_applications WHERE id = ? AND user_id = ?', [id, userId]);
  if (!result.changes) throw new HttpError(404, 'Application not found');
}

async function getDashboard(userId) {
  const byStatus = await db.all('SELECT status, COUNT(*) AS count FROM job_applications WHERE user_id = ? GROUP BY status', [userId]);
  const byMonth = await db.all(
    `SELECT strftime('%Y-%m', created_at) AS month, COUNT(*) AS count
     FROM job_applications
     WHERE user_id = ?
     GROUP BY strftime('%Y-%m', created_at)
     ORDER BY month ASC`,
    [userId],
  );
  return { byStatus, byMonth };
}

module.exports = { createApplication, listApplications, updateApplication, deleteApplication, getDashboard };
