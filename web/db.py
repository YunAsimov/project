"""MySQL-backed account store with strong password hashing.

Passwords are never stored in plaintext or reversibly encrypted. Each password
is hashed with **scrypt** (a memory-hard KDF, from the standard library's
hashlib) using a fresh 16-byte random salt per user. Only (salt, hash) is
stored; verification recomputes the hash and compares in constant time.

This module handles client-server *account* authentication only (kept simple,
as the project focuses on the end-to-end protocol). It is independent of the
E2EE identity keys, which remain local to each endpoint.

Configuration via environment variables (with defaults):
    MYSQL_HOST (127.0.0.1)  MYSQL_PORT (3306)
    MYSQL_USER (root)       MYSQL_PASSWORD ('')   MYSQL_DB (e2ee_chat)
"""

from __future__ import annotations

import hashlib
import hmac
import os

import pymysql

# scrypt cost parameters (OWASP-recommended interactive baseline).
_SCRYPT = dict(n=16384, r=8, p=1, dklen=32)
_SALT_LEN = 16


def _config() -> dict:
    return {
        "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.environ.get("MYSQL_PORT", "3306")),
        "user": os.environ.get("MYSQL_USER", "root"),
        "password": os.environ.get("MYSQL_PASSWORD", ""),
        "db": os.environ.get("MYSQL_DB", "e2ee_chat"),
    }


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)


class UserDB:
    """Account table backed by MySQL: username + scrypt(salt, password)."""

    def __init__(self, **overrides) -> None:
        self.cfg = {**_config(), **overrides}

    def _connect(self, with_db: bool = True):
        kw = dict(
            host=self.cfg["host"], port=self.cfg["port"],
            user=self.cfg["user"], password=self.cfg["password"],
            charset="utf8mb4", autocommit=True, connect_timeout=5,
        )
        if with_db:
            kw["database"] = self.cfg["db"]
        return pymysql.connect(**kw)

    def init(self) -> None:
        """Create the database and table if they do not exist."""
        db = self.cfg["db"]
        conn = self._connect(with_db=False)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{db}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                cur.execute(f"USE `{db}`")
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS users ("
                    "  username VARCHAR(64) PRIMARY KEY,"
                    "  salt VARBINARY(16) NOT NULL,"
                    "  pw_hash VARBINARY(32) NOT NULL,"
                    "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
                    ") ENGINE=InnoDB")
        finally:
            conn.close()

    def exists(self, username: str) -> bool:
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM users WHERE username=%s", (username,))
                return cur.fetchone() is not None
        finally:
            conn.close()

    def create(self, username: str, password: str) -> bool:
        """Register a new user. Returns False if the username is taken."""
        salt = os.urandom(_SALT_LEN)
        pw_hash = _hash_password(password, salt)
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, salt, pw_hash) VALUES (%s, %s, %s)",
                    (username, salt, pw_hash))
            return True
        except pymysql.err.IntegrityError:
            return False
        finally:
            conn.close()

    def verify(self, username: str, password: str) -> bool:
        """Constant-time password check against the stored scrypt hash."""
        conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT salt, pw_hash FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
        finally:
            conn.close()
        if row is None:
            return False
        salt, stored = row
        return hmac.compare_digest(_hash_password(password, salt), stored)
