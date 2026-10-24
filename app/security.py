"""Cryptographic helpers: passwords, session tokens, file encryption, HMAC."""
import hashlib
import hmac
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Passwords (scrypt via Werkzeug)
# ---------------------------------------------------------------------------
# A real hash of a random string. Verifying against it when the email does not
# exist makes "unknown user" take as long as "wrong password", so response
# time does not reveal which emails have accounts.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method="scrypt")

MIN_PASSWORD_LENGTH = 12
# scrypt in production. The test harness swaps in a cheap method so the suite
# runs in seconds; nothing outside tests/ changes this.
HASH_METHOD = "scrypt"


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=HASH_METHOD)


def verify_password(password_hash: str | None, password: str) -> bool:
    if password_hash is None:
        check_password_hash(_DUMMY_HASH, password)
        return False
    return check_password_hash(password_hash, password)


def password_problem(password: str) -> str | None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > 256:
        return "Password is too long."
    return None


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equal(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def new_id() -> str:
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# File encryption: envelope encryption with AES-256-GCM.
# ---------------------------------------------------------------------------
def encrypt_blob(master_key: bytes, blob_id: str, plaintext: bytes) -> dict:
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    # blob_id is bound in as associated data: ciphertext copied into another
    # row will fail to decrypt.
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, blob_id.encode())
    key_nonce = secrets.token_bytes(12)
    wrapped_key = AESGCM(master_key).encrypt(key_nonce, data_key, b"tv-key:" + blob_id.encode())
    return {"nonce": nonce, "ciphertext": ciphertext, "key_nonce": key_nonce, "wrapped_key": wrapped_key}


def decrypt_blob(master_key: bytes, blob_id: str, row) -> bytes:
    data_key = AESGCM(master_key).decrypt(row["key_nonce"], row["wrapped_key"], b"tv-key:" + blob_id.encode())
    return AESGCM(data_key).decrypt(row["nonce"], row["ciphertext"], blob_id.encode())


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------
GENESIS_HASH = "0" * 64


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def audit_hmac(audit_key: bytes, prev_hash: str, record: dict) -> str:
    message = (prev_hash + "|" + canonical_json(record)).encode()
    return hmac.new(audit_key, message, hashlib.sha256).hexdigest()
