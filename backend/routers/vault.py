from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
import uuid
from database import get_connection
from auth_utils import get_current_user

router = APIRouter()

LOGIN_TYPES = ["email_password", "google_sso", "github_sso", "apple_sso", "microsoft_sso", "other"]

class VaultEntryCreate(BaseModel):
    site_name: str
    site_url: Optional[str] = None
    login_type: str = "email_password"
    encrypted_username: Optional[str] = None
    encrypted_password: Optional[str] = None
    encrypted_notes: Optional[str] = None
    favicon_url: Optional[str] = None

class VaultEntryUpdate(BaseModel):
    site_name: Optional[str] = None
    site_url: Optional[str] = None
    login_type: Optional[str] = None
    encrypted_username: Optional[str] = None
    encrypted_password: Optional[str] = None
    encrypted_notes: Optional[str] = None
    favicon_url: Optional[str] = None

@router.get("/entries")
def list_entries(current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    entries = conn.execute(
        "SELECT * FROM vault_entries WHERE user_id = ? ORDER BY site_name ASC",
        (current_user["id"],)
    ).fetchall()
    conn.close()
    return [dict(e) for e in entries]

@router.post("/entries")
def create_entry(entry: VaultEntryCreate, current_user: dict = Depends(get_current_user)):
    if entry.login_type not in LOGIN_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid login_type. Must be one of: {LOGIN_TYPES}")

    entry_id = str(uuid.uuid4())
    conn = get_connection()
    conn.execute("""
        INSERT INTO vault_entries
        (id, user_id, site_name, site_url, login_type, encrypted_username, encrypted_password, encrypted_notes, favicon_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry_id, current_user["id"], entry.site_name, entry.site_url,
        entry.login_type, entry.encrypted_username, entry.encrypted_password,
        entry.encrypted_notes, entry.favicon_url
    ))
    conn.commit()
    new_entry = conn.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
    conn.close()
    return dict(new_entry)

@router.put("/entries/{entry_id}")
def update_entry(entry_id: str, entry: VaultEntryUpdate, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    existing = conn.execute(
        "SELECT * FROM vault_entries WHERE id = ? AND user_id = ?",
        (entry_id, current_user["id"])
    ).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Entry not found")

    updates = {k: v for k, v in entry.model_dump().items() if v is not None}
    if not updates:
        conn.close()
        return dict(existing)

    updates["updated_at"] = "datetime('now')"
    set_clause = ", ".join([f"{k} = ?" for k in updates if k != "updated_at"])
    set_clause += ", updated_at = datetime('now')"
    values = [v for k, v in updates.items() if k != "updated_at"]
    values.extend([entry_id, current_user["id"]])

    conn.execute(
        f"UPDATE vault_entries SET {set_clause} WHERE id = ? AND user_id = ?",
        values
    )
    conn.commit()
    updated = conn.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
    conn.close()
    return dict(updated)

@router.delete("/entries/{entry_id}")
def delete_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM vault_entries WHERE id = ? AND user_id = ?",
        (entry_id, current_user["id"])
    ).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Entry not found")

    conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}

@router.get("/entries/search/{query}")
def search_entries(query: str, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    entries = conn.execute(
        "SELECT * FROM vault_entries WHERE user_id = ? AND site_name LIKE ? ORDER BY site_name ASC",
        (current_user["id"], f"%{query}%")
    ).fetchall()
    conn.close()
    return [dict(e) for e in entries]
