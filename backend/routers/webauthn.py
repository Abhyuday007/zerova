from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
import uuid, json, base64, secrets
from datetime import datetime, timedelta, timezone
from database import get_connection
from auth_utils import get_current_user, create_access_token

router = APIRouter()

RP_ID = "zerova-seven.vercel.app"  # Change to your domain in prod e.g. "vault.yourdomain.com"
RP_NAME = "Personal Vault"
CHALLENGE_TTL_SECONDS = 120

# ── helpers ──────────────────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)

def new_challenge() -> str:
    return b64url_encode(secrets.token_bytes(32))

# ── schemas ───────────────────────────────────────────────────────────────────

class RegisterBeginResponse(BaseModel):
    challenge: str
    rp: dict
    user: dict
    pubKeyCredParams: list
    timeout: int
    attestation: str
    authenticatorSelection: dict

class RegisterFinishRequest(BaseModel):
    credential_id: str
    public_key: str          # client sends the raw public key bytes as b64url
    attestation_object: str  # b64url
    client_data_json: str    # b64url
    device_name: Optional[str] = "My Device"

class AuthBeginResponse(BaseModel):
    challenge: str
    timeout: int
    rpId: str
    allowCredentials: list
    userVerification: str

class AuthFinishRequest(BaseModel):
    credential_id: str
    authenticator_data: str   # b64url
    client_data_json: str     # b64url
    signature: str            # b64url
    username: str             # needed to look up the user before token is issued

# ── registration ──────────────────────────────────────────────────────────────

@router.post("/register/begin")
def register_begin(current_user: dict = Depends(get_current_user)):
    challenge = new_challenge()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=CHALLENGE_TTL_SECONDS)).isoformat()

    conn = get_connection()
    conn.execute(
        "INSERT INTO webauthn_challenges (id, user_id, challenge, type, expires_at) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), current_user["id"], challenge, "registration", expires_at)
    )
    conn.commit()
    conn.close()

    return {
        "challenge": challenge,
        "rp": {"id": RP_ID, "name": RP_NAME},
        "user": {
            "id": b64url_encode(str(current_user["id"]).encode()),
            "name": current_user["username"],
            "displayName": current_user["username"]
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},   # ES256
            {"type": "public-key", "alg": -257},  # RS256
        ],
        "timeout": CHALLENGE_TTL_SECONDS * 1000,
        "attestation": "none",
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",  # device biometrics only
            "userVerification": "required",
            "residentKey": "preferred"
        }
    }

@router.post("/register/finish")
def register_finish(req: RegisterFinishRequest, current_user: dict = Depends(get_current_user)):
    conn = get_connection()

    # Verify a valid unexpired challenge exists
    challenge_row = conn.execute("""
        SELECT * FROM webauthn_challenges
        WHERE user_id = ? AND type = 'registration'
        AND expires_at > datetime('now')
        ORDER BY expires_at DESC LIMIT 1
    """, (current_user["id"],)).fetchone()

    if not challenge_row:
        conn.close()
        raise HTTPException(status_code=400, detail="No valid challenge found or challenge expired")

    # Clean up used challenge
    conn.execute("DELETE FROM webauthn_challenges WHERE id = ?", (challenge_row["id"],))

    # Check for duplicate credential
    existing = conn.execute(
        "SELECT id FROM webauthn_credentials WHERE credential_id = ?",
        (req.credential_id,)
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Credential already registered")

    cred_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO webauthn_credentials
        (id, user_id, credential_id, public_key, sign_count, device_name)
        VALUES (?, ?, ?, ?, 0, ?)
    """, (cred_id, current_user["id"], req.credential_id, req.public_key, req.device_name))
    conn.commit()
    conn.close()

    return {"registered": True, "device_name": req.device_name}

# ── authentication ─────────────────────────────────────────────────────────────

@router.post("/auth/begin")
def auth_begin(body: dict):
    username = body.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    credentials = conn.execute(
        "SELECT credential_id FROM webauthn_credentials WHERE user_id = ?",
        (user["id"],)
    ).fetchall()

    if not credentials:
        conn.close()
        raise HTTPException(status_code=400, detail="No biometric credentials registered for this account")

    challenge = new_challenge()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=CHALLENGE_TTL_SECONDS)).isoformat()

    conn.execute(
        "INSERT INTO webauthn_challenges (id, user_id, challenge, type, expires_at) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), user["id"], challenge, "authentication", expires_at)
    )
    conn.commit()
    conn.close()

    return {
        "challenge": challenge,
        "timeout": CHALLENGE_TTL_SECONDS * 1000,
        "rpId": RP_ID,
        "allowCredentials": [
            {"type": "public-key", "id": c["credential_id"]} for c in credentials
        ],
        "userVerification": "required"
    }

@router.post("/auth/finish")
def auth_finish(req: AuthFinishRequest):
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # Verify challenge
    challenge_row = conn.execute("""
        SELECT * FROM webauthn_challenges
        WHERE user_id = ? AND type = 'authentication'
        AND expires_at > datetime('now')
        ORDER BY expires_at DESC LIMIT 1
    """, (user["id"],)).fetchone()

    if not challenge_row:
        conn.close()
        raise HTTPException(status_code=400, detail="No valid challenge or challenge expired")

    # Verify credential belongs to this user
    cred = conn.execute("""
        SELECT * FROM webauthn_credentials
        WHERE user_id = ? AND credential_id = ?
    """, (user["id"], req.credential_id)).fetchone()

    if not cred:
        conn.close()
        raise HTTPException(status_code=401, detail="Credential not found for this user")

    # Clean up challenge + update last_used + increment sign_count
    conn.execute("DELETE FROM webauthn_challenges WHERE id = ?", (challenge_row["id"],))
    conn.execute("""
        UPDATE webauthn_credentials
        SET last_used = datetime('now'), sign_count = sign_count + 1
        WHERE id = ?
    """, (cred["id"],))
    conn.commit()
    conn.close()

    token = create_access_token(user["id"], user["username"])
    return {"token": token, "username": user["username"], "user_id": user["id"]}

# ── list / remove registered devices ──────────────────────────────────────────

@router.get("/devices")
def list_devices(current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    devices = conn.execute(
        "SELECT id, device_name, created_at, last_used FROM webauthn_credentials WHERE user_id = ?",
        (current_user["id"],)
    ).fetchall()
    conn.close()
    return [dict(d) for d in devices]

@router.delete("/devices/{device_id}")
def remove_device(device_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM webauthn_credentials WHERE id = ? AND user_id = ?",
        (device_id, current_user["id"])
    ).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    conn.execute("DELETE FROM webauthn_credentials WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return {"removed": True}
