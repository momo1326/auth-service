# auth-service

Simple authentication service with:
- User signup and login
- Hashed passwords (bcrypt)
- JWT access + refresh tokens with rotation
- SQLite persistence (users + refresh tokens)
- Login protection (rate limiting + temporary lockouts)
- Session management (list sessions + logout all devices)

## Endpoints
- POST `/signup` `{ "email", "password" }` -> `{ accessToken, refreshToken }`
- POST `/login`  `{ "email", "password" }` -> `{ accessToken, refreshToken }`
- POST `/refresh` `{ "refreshToken" }` -> `{ accessToken, refreshToken }`
- POST `/logout` `{ "refreshToken" }` -> `204`
- POST `/logout-all` (requires `Authorization: Bearer <accessToken>`) -> `204`
- GET `/sessions` (requires `Authorization: Bearer <accessToken>`) -> list active refresh sessions
- GET `/me` (requires `Authorization: Bearer <accessToken>`) -> user info

## Setup
1. Copy `.env.example` to `.env` and set secrets:
   - `ACCESS_TOKEN_SECRET`
   - `REFRESH_TOKEN_SECRET`
   - `PORT` (optional)
   - `TRUST_PROXY` (`true` only when deployed behind a trusted reverse proxy)
2. Install and run:
   ```bash
   npm install
   npm start
   ```

## Example
- Signup:
  ```bash
  curl -X POST http://localhost:3000/signup \
    -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com","password":"StrongP@ssw0rd"}'
  ```

- Login:
  ```bash
  curl -X POST http://localhost:3000/login \
    -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com","password":"StrongP@ssw0rd"}'
  ```

- Refresh:
  ```bash
  curl -X POST http://localhost:3000/refresh \
    -H "Content-Type: application/json" \
    -d '{"refreshToken":"<token>"}'
  ```

## Security behavior
- Emails are normalized (lowercased + trimmed) to avoid duplicate account variants.
- Passwords must be 8-72 chars with upper/lowercase letters, number, and symbol.
- Failed logins are tracked by `email + IP`, with lockout after repeated failures.
- Refresh tokens are stored hashed, rotated on use, and revoked on suspicious replay.
- Per-session refresh rate limiting (max 10 refreshes/hour).
- Response hardening headers are set by default (`nosniff`, `DENY`, `no-referrer`).
- Service fails fast at startup if required JWT secrets are missing.

## Planned improvements
- Add MFA (TOTP / WebAuthn).
- Add email verification and password reset flow.
- Store audit logs for security events.
- Add configurable CORS allowlist for browser-based clients.
