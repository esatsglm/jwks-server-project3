import base64
import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


DB_FILE = Path(__file__).resolve().parent / "totally_not_my_privateKeys.db"


@dataclass
class KeyEntry:
    kid: int
    private_key: rsa.RSAPrivateKey
    expires_at: int


class KeyStore:
    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self._initialize_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_file)

    def _get_fernet(self):
        secret = os.environ.get("NOT_MY_KEY")

        if not secret:
            raise RuntimeError(
                "Missing NOT_MY_KEY environment variable. "
                "Set it before running the server."
            )

        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        return Fernet(key)

    def _encrypt_private_key(self, pem_bytes: bytes) -> bytes:
        return self._get_fernet().encrypt(pem_bytes)

    def _decrypt_private_key(self, encrypted_bytes: bytes) -> bytes:
        return self._get_fernet().decrypt(encrypted_bytes)

    def _initialize_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_ip TEXT NOT NULL,
                    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )

            conn.commit()

        self._ensure_startup_keys()

    def _ensure_startup_keys(self):
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM keys")
            count = cursor.fetchone()[0]

            if count == 0:
                expired_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                valid_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )

                self._insert_key(conn, expired_key, now - 3600)
                self._insert_key(conn, valid_key, now + 3600)
                conn.commit()

    def _insert_key(self, conn, private_key: rsa.RSAPrivateKey, exp: int):
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        encrypted_pem = self._encrypt_private_key(pem)

        conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (encrypted_pem, exp),
        )

    def _row_to_key_entry(self, row) -> KeyEntry:
        kid, encrypted_pem, exp = row

        pem_bytes = self._decrypt_private_key(encrypted_pem)

        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None,
        )

        return KeyEntry(kid=kid, private_key=private_key, expires_at=exp)

    def get_valid_key(self) -> KeyEntry | None:
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY exp ASC
                LIMIT 1
                """,
                (now,),
            )
            row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_key_entry(row)

    def get_expired_key(self) -> KeyEntry | None:
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (now,),
            )
            row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_key_entry(row)

    def get_unexpired_keys(self) -> list[KeyEntry]:
        now = int(time.time())

        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY kid ASC
                """,
                (now,),
            )
            rows = cursor.fetchall()

        return [self._row_to_key_entry(row) for row in rows]

    def create_user(self, username: str, email: str, password_hash: str):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash),
            )
            conn.commit()

    def get_user_by_username(self, username: str):
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, username, password_hash, email
                FROM users
                WHERE username = ?
                """,
                (username,),
            )
            return cursor.fetchone()

    def update_last_login(self, user_id: int):
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE users
                SET last_login = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (user_id,),
            )
            conn.commit()

    def log_auth_request(self, request_ip: str, user_id: int | None):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO auth_logs (request_ip, user_id)
                VALUES (?, ?)
                """,
                (request_ip, user_id),
            )
            conn.commit()