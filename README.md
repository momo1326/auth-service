# Job Application Tracker SaaS API

Production-style SaaS starter built with Express + JWT auth + SQLite (easy local development; can be swapped to PostgreSQL).

## Included features

- JWT authentication with access + refresh tokens and rotation.
- Password hashing with bcrypt.
- Role-based access (`user`, `admin`).
- Email verification flow (token generated and logged via simulated email service).
- Password reset flow.
- Rate-limited auth endpoints.
- Clean architecture:

```txt
src/
  controllers/
  services/
  routes/
  middleware/
  models/
  utils/
```

- Job application CRUD with:
  - filtering (`status`, `search`)
  - sorting (`created_at`, `company`, `status`)
  - pagination (`page`, `pageSize`)
- Dashboard analytics:
  - count by status
  - count by month
- Logging + centralized error middleware.

## API routes

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/verify-email`
- `POST /api/auth/password-reset/request`
- `POST /api/auth/password-reset/confirm`
- `GET /api/auth/me`
- `GET /api/dashboard`
- `GET /api/applications`
- `POST /api/applications`
- `PATCH /api/applications/:id`
- `DELETE /api/applications/:id`
- `GET /api/admin/users` (admin only)

## Run locally

```bash
npm install
ACCESS_TOKEN_SECRET=dev-access REFRESH_TOKEN_SECRET=dev-refresh npm start
```

## Deployment notes

- Backend: Render / Railway
- DB: Neon PostgreSQL (recommended for production)
- Frontend (if separated): Vercel

To deploy, convert `src/models/db.js` queries to your PostgreSQL adapter/ORM (Prisma/Drizzle), then set managed DB env variables.
