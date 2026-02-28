# app/crypto.py — BitGuard key management
# 
# Strategy:
#   - On first run, generate a random AES-256 key and save it to .key_db
#   - On subsequent runs, load the key from .key_db
#   - The extension encrypts with the same key (exported via /vault/key on first setup)
#   - Format stored in DB: base64( IV [12 bytes] + ciphertext + GCM tag [16 bytes] )

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = ".key_db"

# ── Key persistence ────────────────────────────────────────────────────────────

def load_or_create_key() -> bytes:
    """Load the AES-256 key from .key_db, or generate and save it on first run."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError(f".key_db exists but contains {len(key)} bytes (expected 32). File may be corrupt.")
        return key

    # First run: generate a new 256-bit key
    key = os.urandom(32)
    with open(KEY_FILE, "wb") as f:
        f.write(key)

    # Warn the user to back this up
    print("=" * 60)
    print("  BitGuard: NEW ENCRYPTION KEY GENERATED")
    print(f"  Saved to: {os.path.abspath(KEY_FILE)}")
    print("  ⚠  Back this file up — losing it means losing all vault data.")
    print("=" * 60)

    return key


# Singleton — load once at import time
_KEY: bytes = load_or_create_key()


# ── Encrypt / Decrypt ──────────────────────────────────────────────────────────

def encrypt(plaintext: str) -> str:
    """
    Encrypt a UTF-8 string with AES-256-GCM.
    Returns base64( iv[12] + ciphertext + tag[16] )
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(_KEY)
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)

    combined = iv + ciphertext_and_tag
    return base64.b64encode(combined).decode("utf-8")


def decrypt(data_b64: str) -> str:
    """
    Decrypt a base64-encoded AES-256-GCM blob.
    Input: base64( iv[12] + ciphertext + tag[16] )
    Returns the original UTF-8 plaintext.
    """
    combined = base64.b64decode(data_b64)

    if len(combined) < 12 + 16:
        raise ValueError("Ciphertext too short — likely not encrypted with this scheme.")

    iv = combined[:12]
    ciphertext_and_tag = combined[12:]

    aesgcm = AESGCM(_KEY)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
    return plaintext_bytes.decode("utf-8")


def get_key_b64() -> str:
    """Return the raw key as base64 — used once to configure the extension."""
    return base64.b64encode(_KEY).decode("utf-8")
