import sqlite3
from datetime import datetime
import os

SQLITE_DB = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Login Attempts Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success INTEGER,
        ml_prediction INTEGER DEFAULT 0
    )
    ''')

    # Attack Logs Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        ip_address TEXT,
        attack_type TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        action_taken TEXT
    )
    ''')

    # ── NEW: Blocked IPs Table ──────────────────────────────
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        reason TEXT,
        blocked_by TEXT DEFAULT 'admin',
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    # ───────────────────────────────────────────────────────

    # Create Admin User if not exists
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        from werkzeug.security import generate_password_hash
        admin_pass = generate_password_hash('admin123')
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ('admin', 'admin@example.com', admin_pass, 'admin')
        )

    conn.commit()
    conn.close()
    print("Database initialized.")

if __name__ == '__main__':
    init_db()