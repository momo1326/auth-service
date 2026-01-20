# auth-service

Simple authentication service with:
- User signup and login
- Hashed passwords (bcrypt)
- JWT access + refresh tokens
- SQLite persistence (users + refresh tokens)

Endpoints
- POST /signup { "email", "password" } -> { accessToken, refreshToken }
- POST /login  { "email", "password" } -> { accessToken, refreshToken }
- POST /refresh { "refreshToken" } -> { accessToken, refreshToken }
- POST /logout { "refreshToken" } -> 204
- GET /me (requires Authorization: Bearer <accessToken>) -> user info

Setup
1. Copy `.env.example` to `.env` and set secrets:
   - ACCESS_TOKEN_SECRET
   - REFRESH_TOKEN_SECRET
   - PORT (optional)
2. Install and run:
   npm install
   npm start

Example
- Signup:
  curl -X POST http://localhost:3000/signup -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"secret"}'

- Login:
  curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email":"alice@example.com","password":"secret"}'

- Refresh:
  curl -X POST http://localhost:3000/refresh -H "Content-Type: application/json" -d '{"refreshToken":"<token>"}'

Notes
- Refresh tokens are stored in the DB with a tokenId and rotated on use.
- Access token TTL: configurable via env (default 15m)
- Refresh token TTL: configurable via env (default 7d)