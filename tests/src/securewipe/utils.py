"""
securewipe.utils

Convenience utilities for secure memory operations.
"""

from __future__ import annotations

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of two byte sequences.
    Returns True if equal, False otherwise.
    Avoids timing attacks.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def secure_clear(buf: bytearray | memoryview) -> None:
    """
    Securely zero a mutable buffer in-place.
    Works for bytearray or memoryview.
    """
    if not isinstance(buf, (bytearray, memoryview)):
        raise TypeError("buf must be bytearray or memoryview")
    for i in range(len(buf)):
        buf[i] = 0
