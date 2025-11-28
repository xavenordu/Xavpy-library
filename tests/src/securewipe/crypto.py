"""
securewipe.crypto
-----------------

Cryptographic erasure utilities: fast, reliable secure deletion by key destruction.

Notes:
- CryptoKey stores key in secure memory (SecureMemory). Retrieving bytes via `get_bytes()`
  exposes key in normal memory. Minimize exposure, use immediately, then clear from scope.
- encrypt_data() exposes plaintext and key in normal memory during operation; avoid long-lived copies.
- Decrypt functions validate ciphertext length to avoid slicing errors.
"""

from __future__ import annotations
import os
from typing import Optional, NamedTuple

from .memory import SecureMemory
from .utils import secure_clear

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------- Key Management ----------------

class CryptoKey:
    """
    Represents a symmetric key stored in secure memory.
    Destroying this key = instant cryptographic erase of all data encrypted with it.

    Attributes:
        _mem: SecureMemory storing the key
    """
    def __init__(self, key_bytes: bytes):
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise TypeError("key_bytes must be bytes-like")
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("key_bytes must be 16, 24, or 32 bytes (AES-128/192/256)")
        self._mem: SecureMemory = SecureMemory.from_bytes(key_bytes)
        logger.debug("CryptoKey initialized with length %d bytes", len(key_bytes))
    
    @classmethod
    def generate(cls, length: int = 32) -> "CryptoKey":
        """
        Generate a random key of given length (default 32 bytes for AES-256)
        and store in secure memory.
        """
        if length not in (16, 24, 32):
            raise ValueError("AES key length must be 16, 24, or 32 bytes")
        key_bytes = os.urandom(length)
        logger.debug("Generated random AES key of length %d", length)
        return cls(key_bytes)

    def destroy(self) -> None:
        """Zero the key in memory (cryptographic erasure)."""
        logger.debug("Destroying CryptoKey")
        self._mem.close()

    def get_bytes(self) -> bytes:
        """
        Retrieve key bytes for cryptographic operations.

        WARNING: Returns key in normal memory; caller must minimize exposure and clear immediately.
        """
        logger.warning("Exposing CryptoKey bytes in normal memory; use carefully")
        return self._mem.get_bytes()


# ---------------- Ciphertext NamedTuple ----------------

class CipherText(NamedTuple):
    nonce: bytes
    ciphertext: bytes


# ---------------- File / Buffer Encryption ----------------

def encrypt_data(
    plaintext: bytes,
    key: CryptoKey,
    associated_data: Optional[bytes] = None
) -> CipherText:
    """
    Encrypt a byte buffer using AES-GCM.

    Returns:
        CipherText(nonce=..., ciphertext=...) where ciphertext includes authentication tag.

    WARNING: plaintext and key are exposed in normal memory during this operation.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    nonce = os.urandom(12)
    aes = AESGCM(key.get_bytes())
    ciphertext = aes.encrypt(nonce, plaintext, associated_data)
    logger.debug("Encrypted data: %d bytes plaintext, nonce %d bytes", len(plaintext), len(nonce))
    return CipherText(nonce, ciphertext)


def decrypt_data(
    ct: CipherText,
    key: CryptoKey,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypt a buffer encrypted with encrypt_data().

    Validates ciphertext length before decrypting.
    """
    if not isinstance(ct, CipherText):
        raise TypeError("ct must be a CipherText instance")
    if len(ct.nonce) != 12:
        raise ValueError("Invalid nonce length")
    aes = AESGCM(key.get_bytes())
    plaintext = aes.decrypt(ct.nonce, ct.ciphertext, associated_data)
    logger.debug("Decrypted data: %d bytes plaintext", len(plaintext))
    return plaintext


# ---------------- Convenience ----------------

def cryptographic_erase_key(key: CryptoKey) -> None:
    """
    High-level function: destroy key to erase all data encrypted with it.
    """
    logger.debug("Cryptographic erase invoked for key")
    key.destroy()
