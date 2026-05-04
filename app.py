from collections import defaultdict, deque
import base64
import time
import uuid

from argon2 import PasswordHasher
from flask import Flask, jsonify, request
import jwt

from keys import KeyStore


app = Flask(__name__)
keystore = KeyStore()
password_hasher = PasswordHasher()

RATE_LIMIT = 10
RATE_WINDOW_SECONDS = 1
request_history = defaultdict(deque)


def int_to_base64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8
    n_bytes = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("utf-8")


def is_rate_limited(ip_address: str) -> bool:
    now = time.time()
    history = request_history[ip_address]

    while history and now - history[0] > RATE_WINDOW_SECONDS:
        history.popleft()

    if len(history) >= RATE_LIMIT:
        return True

    history.append(now)
    return False


@app.get("/.well-known/jwks.json")
def jwks():
    keys = []

    for key_entry in keystore.get_unexpired_keys():
        public_key = key_entry.private_key.public_key()
        numbers = public_key.public_numbers()

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(key_entry.kid),
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
        }
        keys.append(jwk)

    return jsonify({"keys": keys}), 200


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")

    if not username or not email:
        return jsonify({"error": "username and email are required"}), 400

    password = str(uuid.uuid4())
    password_hash = password_hasher.hash(password)

    try:
        keystore.create_user(username, email, password_hash)
    except Exception:
        return jsonify({"error": "username or email already exists"}), 409

    return jsonify({"password": password}), 201


@app.post("/auth")
def auth():
    client_ip = request.remote_addr or "unknown"

    if is_rate_limited(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429

    now = int(time.time())
    expired_flag = "expired" in request.args

    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    user_id = None

    if username and password:
        user = keystore.get_user_by_username(username)

        if user is None:
            return jsonify({"error": "Invalid username or password"}), 401

        user_id, stored_username, password_hash, email = user

        try:
            password_hasher.verify(password_hash, password)
        except Exception:
            return jsonify({"error": "Invalid username or password"}), 401

        keystore.update_last_login(user_id)

    if expired_flag:
        key_entry = keystore.get_expired_key()
        if key_entry is None:
            return jsonify({"error": "No expired key found"}), 500
        exp_time = key_entry.expires_at
    else:
        key_entry = keystore.get_valid_key()
        if key_entry is None:
            return jsonify({"error": "No valid key found"}), 500
        exp_time = now + 300

    payload = {
        "sub": username if username else "fake-user",
        "iat": now,
        "exp": exp_time,
    }

    token = jwt.encode(
        payload,
        key_entry.private_key,
        algorithm="RS256",
        headers={"kid": str(key_entry.kid)},
    )

    keystore.log_auth_request(client_ip, user_id)

    return jsonify({"token": token}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)