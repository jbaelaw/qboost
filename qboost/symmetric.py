from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .utils import DecryptionError, quantum_random, shake256

_SALT_LEN = 32
_NONCE_LEN = 12
_KEY_LEN = 32


def derive_key(
    password: str,
    salt: bytes | None = None,
    key_length: int = _KEY_LEN,
) -> tuple[bytes, bytes]:
    if salt is None:
        salt = quantum_random(_SALT_LEN)

    kdf = Scrypt(salt=salt, length=key_length, n=2**16, r=8, p=1)
    scrypt_output = kdf.derive(password.encode("utf-8"))

    key = shake256(scrypt_output + salt + b"qboost-kdf-v1", key_length)
    return key, salt


def encrypt(plaintext: bytes, password: str) -> bytes:
    key, salt = derive_key(password)
    nonce = quantum_random(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt(ciphertext: bytes, password: str) -> bytes:
    min_len = _SALT_LEN + _NONCE_LEN + 16  # salt + nonce + tag
    if len(ciphertext) < min_len:
        raise DecryptionError("Ciphertext too short")

    salt = ciphertext[:_SALT_LEN]
    nonce = ciphertext[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
    ct = ciphertext[_SALT_LEN + _NONCE_LEN :]

    key, _ = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise DecryptionError("Decryption failed") from e


def encrypt_with_key(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != _KEY_LEN:
        raise ValueError(f"Key must be {_KEY_LEN} bytes")
    nonce = quantum_random(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_with_key(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != _KEY_LEN:
        raise ValueError(f"Key must be {_KEY_LEN} bytes")

    min_len = _NONCE_LEN + 16
    if len(ciphertext) < min_len:
        raise DecryptionError("Ciphertext too short")

    nonce = ciphertext[:_NONCE_LEN]
    ct = ciphertext[_NONCE_LEN:]

    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise DecryptionError("Decryption failed") from e
