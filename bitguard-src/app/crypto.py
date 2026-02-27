import os
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from .config import (
    PASSWORD_LENGTH,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM
)

def generate_password():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(PASSWORD_LENGTH))

def derive_key(password: str, salt: bytes):
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )

def encrypt_password(plaintext: str, master_password: str):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return encrypted, salt, nonce

def decrypt_password(encrypted, master_password, salt, nonce):
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted, None).decode()