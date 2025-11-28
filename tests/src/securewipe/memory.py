"""
securewipe.memory
-----------------

High-level secure memory API.

Provides:
 - SecureMemory(size or bytes) — allocate an isolated buffer in locked memory
 - secure_alloc(size) — context manager yielding a SecureMemory
 - secret_bytes(b: bytes) — convenience: allocate and copy bytes into secure memory

Implementation notes:
 - Prefers libsodium allocation (sodium_malloc + sodium_mlock + sodium_memzero + sodium_free)
 - Falls back to a ctypes buffer with mlock when libsodium is unavailable (POSIX/Windows VirtualLock)
 - On __del__ or close(), the buffer is zeroed and freed
 - Exposes `read()` and `write()` methods. `get_bytes()` returns a copy — caller must zero
 - mlock may fail on POSIX if size exceeds RLIMIT_MEMLOCK; failure is logged
 - Fallback allocations are safe and logged, even when libsodium unavailable
"""

from __future__ import annotations
import typing as _typing
import ctypes
import contextlib
import os
import logging

from . import _sodium

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# Exceptions
class SecureMemoryError(Exception):
    pass

class SecureMemoryClosed(SecureMemoryError):
    pass


# --- Core SecureMemory class ---
class SecureMemory:
    """Secure memory buffer with locked memory and explicit zeroing."""

    _owner_obj: _typing.Any
    _ptr: _typing.Any
    _mv: _typing.Optional[memoryview]

    def __init__(self, size: int):
        self.size: int = int(size)
        self._closed: bool = False
        self._owner_obj = None
        self._ptr = None
        self._mv = None

        # Allocate using libsodium if available
        if _sodium.have_libsodium():
            ptr, mv = _sodium.sodium_alloc_buf(self.size)
            self._ptr = ptr
            self._mv = memoryview(mv).cast('B')
            try:
                if getattr(_sodium, "sodium_mlock", None):
                    _sodium.sodium_mlock(ptr, self.size)
            except Exception as e:
                logger.warning("mlock failed for SecureMemory allocation: %s", e)
            self._owner_obj = ptr
        else:
            # Fallback: ctypes buffer + memoryview
            buf, mv = _sodium.sodium_alloc_buf(self.size)
            self._ptr = buf
            self._mv = memoryview(mv).cast('B')
            try:
                if getattr(_sodium, "sodium_mlock", None):
                    _sodium.sodium_mlock(buf, self.size)
            except Exception as e:
                logger.warning("mlock failed for fallback SecureMemory: %s", e)
            self._owner_obj = buf

    # ---- Basic operations ----
    def write(self, data: bytes, offset: int = 0) -> None:
        if self._closed:
            raise SecureMemoryClosed("buffer closed")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")
        if offset < 0 or offset + len(data) > self.size:
            raise ValueError("write out of bounds")
        self._mv[offset: offset + len(data)] = data

    def read(self, length: int = None, offset: int = 0) -> bytes:
        if self._closed:
            raise SecureMemoryClosed("buffer closed")
        if length is None:
            length = self.size - offset
        if offset < 0 or offset + length > self.size:
            raise ValueError("read out of bounds")
        return bytes(self._mv[offset: offset + length])

    def get_bytes(self) -> bytes:
        """Return a copy of the secure data as bytes (cannot be zeroed; caller must handle)."""
        return self.read()

    def zero(self) -> None:
        """Explicitly zero the buffer in-place using sodium_memzero or fallback."""
        if self._closed:
            return
        try:
            _sodium.sodium_memzero(self._owner_obj, self.size)
        except Exception as e:
            logger.warning("sodium_memzero failed: %s", e)
            try:
                self._mv[:] = b"\x00" * self.size
            except Exception as e2:
                logger.error("Fallback zeroing failed for SecureMemory: %s", e2)

    def close(self) -> None:
        """Zero and free the buffer. After close, buffer is unusable."""
        if self._closed:
            return
        try:
            self.zero()
        finally:
            try:
                if getattr(_sodium, "sodium_munlock", None):
                    _sodium.sodium_munlock(self._owner_obj, self.size)
            except Exception as e:
                logger.warning("munlock failed for SecureMemory: %s", e)
            try:
                if _sodium.have_libsodium():
                    _sodium.sodium_free(self._owner_obj)
            except Exception as e:
                logger.warning("sodium_free failed for SecureMemory: %s", e)
            self._mv = None
            self._owner_obj = None
            self._ptr = None
            self._closed = True

    # ---- Context management ----
    def __enter__(self) -> "SecureMemory":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # ---- Convenience factories ----
    @classmethod
    def alloc(cls, size: int) -> "SecureMemory":
        return cls(size)

    @classmethod
    def from_bytes(cls, data: bytes) -> "SecureMemory":
        b = cls(len(data))
        b.write(data)
        return b


# ---- Convenience helpers ----
def secure_alloc(size: int) -> _typing.ContextManager[SecureMemory]:
    """Context manager returning a SecureMemory of `size` bytes."""
    return _SecureAllocCtx(size)


class _SecureAllocCtx:
    def __init__(self, size: int):
        self.size = size
        self._obj: _typing.Optional[SecureMemory] = None

    def __enter__(self) -> SecureMemory:
        self._obj = SecureMemory.alloc(self.size)
        return self._obj

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._obj is not None:
                self._obj.close()
        finally:
            self._obj = None


def secret_bytes(data: bytes) -> SecureMemory:
    """Allocate secure memory and copy `data` into it."""
    return SecureMemory.from_bytes(data)
