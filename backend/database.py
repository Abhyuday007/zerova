import sqlite3
import os

DB_PATH = os.getenv("DB_PATH", "vault.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()

    # Master user table — single user vault
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            hashed_master_password TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Vault entries — all sensitive fields are AES-256-GCM encrypted client-side
    # Server only stores ciphertext blobs
    c.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            site_name TEXT NOT NULL,
            site_url TEXT,
            login_type TEXT NOT NULL DEFAULT 'email_password',
            encrypted_username TEXT,
            encrypted_password TEXT,
            encrypted_notes TEXT,
            favicon_url TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # WebAuthn credentials per device
    c.execute("""
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            credential_id TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER DEFAULT 0,
            device_name TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            last_used TEXT
        )
    """)

    # WebAuthn challenges (short-lived)
    c.execute("""
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            challenge TEXT NOT NULL,
            type TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized")
