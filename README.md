# 🔐 Personal Vault

A zero-knowledge password manager with biometric (Touch ID / Face ID) support.

**Architecture:**
- Passwords are encrypted **in your browser** using AES-256-GCM before being sent to the server
- The server stores only ciphertext — it can never read your passwords
- Your master password is used client-side to derive the encryption key via PBKDF2 (310,000 iterations)
- WebAuthn/biometrics for quick access on registered devices

---

## Project Structure

```
vault/
├── backend/          # FastAPI + SQLite
│   ├── main.py
│   ├── database.py
│   ├── auth_utils.py
│   ├── routers/
│   │   ├── auth.py
│   │   ├── vault.py
│   │   └── webauthn.py
│   ├── requirements.txt
│   └── render.yaml
└── frontend/         # React + Vite + TypeScript
    ├── src/
    │   ├── App.tsx
    │   ├── api/client.ts
    │   ├── api/webauthn.ts
    │   ├── hooks/useAuth.tsx
    │   └── utils/crypto.ts
    └── package.json
```

---

## Local Development

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env — set a strong JWT_SECRET

python main.py
# Runs at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

### Frontend

```bash
cd frontend
npm install

cp .env.example .env
# For local dev, leave VITE_API_URL blank (proxy handles it)

npm run dev
# Runs at http://localhost:5173
```

---

## Deploying to Render (Free Tier)

### Step 1 — Push to GitHub

```bash
git init
git add .
git commit -m "initial vault"
git remote add origin https://github.com/YOUR_USERNAME/vault.git
git push -u origin main
```

### Step 2 — Deploy Backend on Render

1. Go to [render.com](https://render.com) → New → Web Service
2. Connect your GitHub repo
3. Set **Root Directory** to `backend`
4. Build command: `pip install -r requirements.txt`
5. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Add environment variables:
   - `JWT_SECRET` → generate a random 64-char string
   - `TOKEN_EXPIRE_HOURS` → `12`
   - `DB_PATH` → `/opt/render/project/src/vault.db`
7. Deploy — note the URL e.g. `https://vault-api-xxxx.onrender.com`

> ⚠️ Free Render tier spins down after 15 min inactivity. First request after sleep takes ~30s. Upgrade to paid ($7/mo) to keep it always-on.

### Step 3 — Update WebAuthn RP_ID

In `backend/routers/webauthn.py`, change:
```python
RP_ID = "localhost"
```
to your **frontend domain** (not the API domain):
```python
RP_ID = "vault-frontend-xxxx.vercel.app"
```
Redeploy the backend.

### Step 4 — Deploy Frontend on Vercel

```bash
npm install -g vercel
cd frontend
vercel
```

Or via Vercel dashboard:
1. Import GitHub repo
2. Set **Root Directory** to `frontend`
3. Add environment variable:
   - `VITE_API_URL` → your Render backend URL
4. Deploy

---

## First Time Setup

1. Open the app → **Create Vault** tab
2. Pick a username and a strong master password
3. **Never forget this master password** — it's never stored anywhere. If you lose it, your vault cannot be recovered.
4. Add your first entry
5. Go to ⚙️ Settings → **Register This Device** to set up Touch ID / Face ID

---

## Adding Biometrics on a New Device

1. Open the app → enter username + master password (required once per device)
2. Go to ⚙️ Settings → Register This Device
3. Name it (e.g. "iPhone 15") → authenticate with Face ID / Touch ID
4. Future logins on that device: enter username → tap "Use Touch ID / Face ID" → enter master password once for key derivation

---

## Security Notes

- **Zero-knowledge**: Server never sees plaintext passwords. Even if the DB leaks, all data is encrypted.
- **PBKDF2**: 310,000 iterations (OWASP 2024 recommended minimum) — makes brute force expensive.
- **AES-256-GCM**: Each field encrypted independently with a random IV.
- **WebAuthn**: Device-local biometrics via the browser's platform authenticator. Credentials never leave the device.
- **Biometric caveat**: After biometric auth you still need to enter the master password once per session for key derivation. This is by design — biometrics only prove identity, not the encryption key.

---

## Features

- ✅ Store email/password credentials
- ✅ Store SSO logins (Google, GitHub, Apple, Microsoft)
- ✅ AES-256-GCM client-side encryption
- ✅ Password generator (length + character set options)
- ✅ Copy username/password to clipboard
- ✅ Search entries
- ✅ Touch ID / Face ID via WebAuthn
- ✅ Manage registered devices
- ✅ JWT auth with configurable expiry
- ✅ Mobile-friendly UI
