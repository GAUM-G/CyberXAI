# Honeypot Website (React + Express + SQL)

This setup adds separate frontend and backend folders while keeping familiar routes for honeypot behavior.

## Structure

- `frontend/` -> React app (Vite)
- `backend/` -> Express API with SQLite DB
- `decoy_files/` -> Shared decoy files served from backend route `/files/:filename`

## Kept Routes

- `GET /` (backend health/info)
- `POST /signup`
- `POST /login`
- `GET /dashboard` (protected, JWT)
- `GET /search?q=...`
- `GET /files`
- `GET /files/:filename`

Frontend routes:

- `/` -> Home + Login
- `/signup` -> Sign Up
- `/dashboard` -> Dashboard panel after login

## Run Backend

```bash
cd backend
npm install
copy .env.example .env
npm run dev
```

## Run Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend: `http://localhost:5173`
Backend: `http://localhost:5000`

## SQL Database

SQLite DB is auto-created at:

- `backend/data/honeypot.db`

No MongoDB required.
