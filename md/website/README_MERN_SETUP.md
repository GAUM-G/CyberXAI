# Attacker-facing company portal (React + Express)

The React service is a fictional employee portal. It is intentionally separated from the Flask analyst dashboard and uses controlled simulations to demonstrate SQL injection and XSS outcomes.

## Structure

- `website/frontend/` -> React app (Vite)
- `website/backend/` -> Express collector, analyst API, and safe decoy-response API
- `website/decoy_files/` -> Shared decoy files served from backend route `/files/:filename`

## Portal Routes

- `GET /` (backend health/info)
- `POST /api/decoy/login`
- `GET /api/decoy/search?q=...`
- `GET /files`
- `GET /files/:filename`

Frontend routes:

- `/` -> Fake company home, employee login, resource search, and decoy files
- All other frontend paths redirect to `/`

The Flask dashboard at `http://127.0.0.1:5050` has separate approved-Gmail signup, email OTP verification, email/password login, and a private account store. Its protected security API calls to the backend are not linked or called by the attacker-facing React application.

## Run Backend

From the project root:

```bash
cd website/backend
npm install
copy .env.example .env
npm run dev
```

## Run Frontend

From the project root, in a separate terminal:

```bash
cd website/frontend
npm install
npm run dev
```

Frontend: `http://localhost:5173`
Backend: `http://localhost:5000`

## Controlled attack outcomes

- Recognized SQL injection input returns fictional rows from `northstar_hr.employee_directory`.
- Recognized XSS input returns fictional browser-cache records and a fake session value.
- React renders every value as text and never executes submitted scripts.
- Attempts continue through the existing honeypot event, IDS, XAI, alert, and simulated-IPS pipeline.

All returned identities use the reserved `.example` domain and are synthetic.
