from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database import get_connection
from auth_utils import hash_password, verify_password, create_access_token

router = APIRouter()

class RegisterRequest(BaseModel):
    username: str
    master_password: str

class LoginRequest(BaseModel):
    username: str
    master_password: str

@router.post("/register")
def register(req: RegisterRequest):
    conn = get_connection()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (req.username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed, salt = hash_password(req.master_password)
    conn.execute(
        "INSERT INTO users (username, hashed_master_password, salt) VALUES (?, ?, ?)",
        (req.username, hashed, salt)
    )
    conn.commit()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
    conn.close()

    token = create_access_token(user["id"], user["username"])
    return {"token": token, "username": user["username"], "user_id": user["id"]}

@router.post("/login")
def login(req: LoginRequest):
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
    conn.close()

    if not user or not verify_password(req.master_password, user["hashed_master_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user["id"], user["username"])
    return {"token": token, "username": user["username"], "user_id": user["id"]}

@router.get("/me")
def me(current_user: dict = __import__('fastapi').Depends(__import__('auth_utils').get_current_user)):
    return {"username": current_user["username"], "user_id": current_user["id"]}
