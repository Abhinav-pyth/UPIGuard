# UPIGuard - Secure UPI Breach Checker

UPIGuard is a privacy-focused utility to check if your UPI IDs are exposed in public datasets or leaks.

## Features
- **Secure Auth**: JWT-based authentication with OTP verification.
- **Privacy First**: UPI IDs are stored only as HMAC-SHA256 hashes in user history.
- **Detailed Reports**: View severity and source of breaches.
- **History Dashboard**: Track your security status over time.
- **Admin Logging**: Internal auditing of plaintext inputs (filesystem-only).

## Local Development

### Prerequisites
- Python 3.9+
- Node.js (optional, for some frontend tools)

### Setup
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Create a `.env` file in `backend/` (see `.env.example` if available, or use the provided defaults).
4. Run the server:
   ```bash
   cd backend
   python -m uvicorn main:app --reload
   ```
5. Open `http://localhost:8000` in your browser.

## Testing
Run the smoke test to verify API functionality:
```bash
cd backend
python smoke_test.py
```

## Vercel Deployment

This project is configured for one-click deployment to Vercel.

### Steps
1. Push this repository to GitHub.
2. Connect the repository to Vercel.
3. Vercel will automatically detect the `vercel.json` configuration.
4. **Environment Variables**: Add `SECRET_KEY` and other variables from `backend/.env` to Vercel's Environment Variables settings.
5. Deploy!

> [!IMPORTANT]
> **Persistence on Vercel**: Vercel uses a stateless filesystem. User accounts and check history (stored in JSON files in `backend/data/`) will NOT persist across deployments or server restarts. For production persistence, migrate the `db.py` logic to a real database like PostgreSQL or MongoDB.

### Vercel Configuration (`vercel.json`)
- **API**: Routed to `backend/main.py` using `@vercel/python`.
- **Frontend**: Served as static files from `frontend/` for optimal performance.
