"""
setup_auth.py  —  Run once to add login credentials to your team.

Usage:
    python setup_auth.py

This adds username + password fields to your existing users
and sets up login credentials for everyone.
"""

import sqlite3, os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "closeapp.db")

# ── Set your team's usernames and passwords here ──────────────────────────────
# Format: (user_id, username, password)
# Change these passwords before sharing with your team!
CREDENTIALS = [
    (1, "joe",     "ChangeMe2026!"),   # Joe  — ADMIN
    (2, "shaun",   "Welcome2026!"),
    (3, "anita",   "Welcome2026!"),
    (4, "mandy",   "Welcome2026!"),
    (5, "kat",     "Welcome2026!"),
    (6, "ali",     "Welcome2026!"),
    (7, "marilyn", "Welcome2026!"),
]


def run():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Add username column if it doesn't exist
    try:
        cur.execute("ALTER TABLE users ADD COLUMN username TEXT")
        print("Added username column")
    except sqlite3.OperationalError:
        print("username column already exists")

    # Add password_hash column if it doesn't exist
    try:
        cur.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        print("Added password_hash column")
    except sqlite3.OperationalError:
        print("password_hash column already exists")

    # Set credentials
    for user_id, username, password in CREDENTIALS:
        hashed = generate_password_hash(password)
        cur.execute(
            "UPDATE users SET username=?, password_hash=? WHERE id=?",
            (username, hashed, user_id)
        )
        print(f"  Set credentials for user {user_id} → username: {username}")

    conn.commit()
    conn.close()

    print("\n✓ Auth setup complete!")
    print("\nLogin credentials:")
    print("─" * 40)
    for user_id, username, password in CREDENTIALS:
        role = "ADMIN" if user_id == 1 else "user"
        print(f"  {username:<12} / {password:<20} [{role}]")
    print("─" * 40)
    print("\n⚠  Share passwords securely and remind team to keep them safe.")
    print("   Restart Flask then open http://127.0.0.1:5000")


if __name__ == "__main__":
    run()
