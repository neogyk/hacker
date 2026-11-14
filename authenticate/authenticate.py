
"""
Simple username/password authentication using only the Python standard library.

Features:
- Passwords hashed with scrypt and a unique random salt per user
- Constant-time hash comparison
- SQLite storage (parameterized queries, so no SQL injection)
- Basic password policy
- Temporary lockout after repeated failed logins
- Generic error messages, so attackers can't tell whether a username exists

Usage:
    python auth.py
"""

import getpass
import hashlib
import hmac
import re
import secrets
import sqlite3
import time

DB_PATH = "users.db"

# scrypt cost parameters (OWASP-recommended range: N=2**15, r=8, p=1 or higher)
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
SALT_BYTES = 16
KEY_BYTES = 32

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class AuthError(Exception):
    """Raised for registration problems (bad username, weak password, etc.)."""


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
        dklen=KEY_BYTES,
    )


def _validate_password(password: str) -> None:
    if len(password) < 10:
        raise AuthError("Password must be at least 10 characters long.")
    if not re.search(r"[a-z]", password):
        raise AuthError("Password must contain a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise AuthError("Password must contain an uppercase letter.")
    if not re.search(r"\d", password):
        raise AuthError("Password must contain a digit.")


class AuthService:
    def __init__(self, db_path: str = DB_PATH):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username        TEXT PRIMARY KEY COLLATE NOCASE,
                salt            BLOB NOT NULL,
                password_hash   BLOB NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    REAL NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.commit()
        # Used to equalize timing when the username doesn't exist
        self._dummy_salt = secrets.token_bytes(SALT_BYTES)

    def register(self, username: str, password: str) -> None:
        if not USERNAME_RE.match(username):
            raise AuthError(
                "Username must be 3-32 characters: letters, digits, _ . -"
            )
        _validate_password(password)

        salt = secrets.token_bytes(SALT_BYTES)
        pw_hash = _hash_password(password, salt)
        try:
            self.conn.execute(
                "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, pw_hash),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            raise AuthError("That username is already taken.")

    def login(self, username: str, password: str) -> bool:
        """Return True on success, False otherwise (never reveals why)."""
        row = self.conn.execute(
            "SELECT salt, password_hash, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if row is None:
            # Do the same work as a real check so timing doesn't leak existence
            _hash_password(password, self._dummy_salt)
            return False

        salt, stored_hash, failed, locked_until = row

        if time.time() < locked_until:
            return False

        candidate = _hash_password(password, salt)
        if hmac.compare_digest(candidate, stored_hash):
            self.conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = 0 "
                "WHERE username = ?",
                (username,),
            )
            self.conn.commit()
            return True

        failed += 1
        locked_until = time.time() + LOCKOUT_SECONDS if failed >= MAX_FAILED_ATTEMPTS else 0
        if failed >= MAX_FAILED_ATTEMPTS:
            failed = 0
        self.conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (failed, locked_until, username),
        )
        self.conn.commit()
        return False

    def change_password(self, username: str, old_password: str, new_password: str) -> None:
        if not self.login(username, old_password):
            raise AuthError("Current username or password is incorrect.")
        _validate_password(new_password)
        salt = secrets.token_bytes(SALT_BYTES)
        self.conn.execute(
            "UPDATE users SET salt = ?, password_hash = ? WHERE username = ?",
            (salt, _hash_password(new_password, salt), username),
        )
        self.conn.commit()


def main() -> None:
    auth = AuthService()
    while True:
        choice = input("\n[r]egister, [l]ogin, [q]uit: ").strip().lower()
        if choice == "q":
            break
        if choice not in ("r", "l"):
            continue

        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")

        if choice == "r":
            try:
                auth.register(username, password)
                print("Registration successful.")
            except AuthError as e:
                print(f"Error: {e}")
        else:
            if auth.login(username, password):
                print(f"Welcome, {username}!")
            else:
                print("Invalid username or password (or account temporarily locked).")


if __name__ == "__main__":
    main()
