# securewipe/memory.py
"""
securewipe.memory
-----------------

High-level secure memory API used by tests.

- SecureMemory(size) / SecureMemory.alloc(size)
- SecureMemory.from_bytes(data) and secret_bytes(data)
- secure_alloc(size) context manager
- close(), zero(), read(), write(), get_bytes()
- Raises SecureMemoryClosed after close()

Implementation:
- Prefer libsodium if _sodium.have_libsodium() is True (keeps existing behavior).
- Fallback: safe bytearray-backed buffer exposed via memoryview.
- Deterministic zeroing via sodium_memzero (when available) or memoryview writes.
"""

from __future__ import annotations
import typing as _typing
import logging
import contextlib

import ctypes

from . import _sodium

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# Public exceptions
class SecureMemoryError(Exception):
    pass


class SecureMemoryClosed(SecureMemoryError):
    pass


# Internal fallback buffer (safe, memoryview-backed)
class _FallbackBuffer:
    def __init__(self, size: int):
        # bytearray supports zero-length; memoryview works on it
        self._buf = bytearray(size)
        self._mv = memoryview(self._buf).cast("B")

    def write(self, offset: int, data: bytes) -> None:
        self._mv[offset: offset + len(data)] = data

    def read(self, offset: int, length: int) -> bytes:
        return bytes(self._mv[offset: offset + length])

    def zero(self) -> None:
        """Deterministic in-place zeroing of the underlying bytearray buffer."""
        if not self._buf:
            return
        try:
            # Use ctypes.memset on the actual bytearray buffer to guarantee in-place write
            buf_len = len(self._buf)
            if buf_len == 0:
                return
            # Obtain address of the bytearray buffer
            c_arr = (ctypes.c_char * buf_len).from_buffer(self._buf)
            addr = ctypes.addressof(c_arr)
            ctypes.memset(addr, 0, buf_len)
            # keep memoryview in sync; we mutated in-place so _mv already reflects it
            return
        except Exception:
            # Fallback to safe python-level write (slower but correct)
            try:
                for i in range(len(self._mv)):
                    self._mv[i] = 0
            except Exception:
                # last resort: replace buffer (not ideal but safe)
                self._buf[:] = b"\x00" * len(self._buf)
                self._mv = memoryview(self._buf).cast("B")
                
    def tobytes(self) -> bytes:
        return self._mv.tobytes()

    def close(self) -> None:
        # zero and release
        try:
            self.zero()
        except Exception:
            pass
        try:
            self._mv.release()
        except Exception:
            pass
        self._mv = None
        self._buf = None


# Core SecureMemory class
class SecureMemory:
    """
    Secure memory buffer.

    Public surface used by tests:
      - alloc(size) / from_bytes(data)
      - write(data, offset=0)
      - read(length=None, offset=0)
      - get_bytes()
      - zero(), close()
      - context manager via secure_alloc()
    """

    def __init__(self, size: int):
        self.size = int(size)
        self._closed = False
        self._use_sodium = False
        self._ptr = None  # libsodium pointer-like, or None for fallback
        self._fallback: _FallbackBuffer | None = None

        # Attempt libsodium allocation first (keep semantics if present)
        try:
            if _sodium.have_libsodium():
                # sodium_alloc_buf should return (ptr, buffer_like) in your wrapper
                ptr, buf_like = _sodium.sodium_alloc_buf(self.size)
                # store pointer and memoryview
                self._use_sodium = True
                self._ptr = ptr
                self._mv = memoryview(buf_like).cast("B") if buf_like is not None else memoryview(bytearray(self.size)).cast("B")
                # try to lock via libsodium if available (best-effort)
                try:
                    if getattr(_sodium, "sodium_mlock", None):
                        _sodium.sodium_mlock(ptr, self.size)
                except Exception:
                    logger.debug("sodium_mlock failed or not available")
                return
        except Exception:
            logger.debug("libsodium not available or failed; falling back to bytearray buffer")

        # Fallback: safe bytearray-backed buffer exposed by memoryview
        self._fallback = _FallbackBuffer(self.size)
        self._mv = self._fallback._mv

    # --- Basic operations ---
    def write(self, data: bytes, offset: int = 0) -> None:
        if self._closed:
            raise SecureMemoryClosed("buffer closed")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")
        if offset < 0 or offset + len(data) > self.size:
            raise ValueError("write out of bounds")
        # memoryview assignment works for sodium-backed or fallback
        self._mv[offset: offset + len(data)] = data

    def read(self, length: int | None = None, offset: int = 0) -> bytes:
        if self._closed:
            raise SecureMemoryClosed("buffer closed")
        if length is None:
            length = self.size - offset
        if offset < 0 or offset + length > self.size:
            raise ValueError("read out of bounds")
        return bytes(self._mv[offset: offset + length])

    def get_bytes(self) -> bytes:
        """Return a copy of the secure data as bytes."""
        return self.read()

    # --- Zeroing ---
    def zero(self) -> None:
        if self._closed:
            return

        # Prefer libsodium memzero if used
        if self._use_sodium:
            try:
                # Primary: libsodium's own memzero (best-effort)
                _sodium.sodium_memzero(self._ptr, self.size)
            except Exception as e:
                logger.debug("sodium_memzero failed: %s", e)

            # Best-effort double-write: if we have a Python-visible buffer, memset it too.
            # This ensures Python-level views (memoryview) observe the change.
            try:
                if getattr(self, "_mv", None) is not None:
                    # attempt to find a writable buffer object (bytearray) backing the mv
                    mv = self._mv
                    # Try to access mv.obj (object that owns the buffer) - may vary by Python impl
                    buf_obj = getattr(mv, "obj", None)
                    if isinstance(buf_obj, (bytearray, memoryview)):
                        # If it's memoryview, try to get its object
                        if isinstance(buf_obj, memoryview):
                            try:
                                buf_obj = buf_obj.obj
                            except Exception:
                                buf_obj = None
                        if isinstance(buf_obj, bytearray):
                            c_arr = (ctypes.c_char * len(buf_obj)).from_buffer(buf_obj)
                            ctypes.memset(ctypes.addressof(c_arr), 0, len(buf_obj))
                            return
                    # If mv exposes a buffer that allows from_buffer, try that
                    try:
                        buf_len = len(mv)
                        if buf_len:
                            c_arr = (ctypes.c_char * buf_len).from_buffer(mv)
                            ctypes.memset(ctypes.addressof(c_arr), 0, buf_len)
                            return
                    except Exception:
                        # ignore and fallback below
                        pass
            except Exception:
                pass

            # If we reach here, we tried sodium and ctypes and they failed; fall through
            # to the generic fallback below.

        # Fallback: try fast ctypes-based zero on fallback buffer
        try:
            if getattr(self, "_fallback", None) is not None and self._fallback is not None:
                self._fallback.zero()
                return
        except Exception:
            logger.debug("fallback.zero() attempt failed, trying safe python fallback")

        # Last resort: in-place memoryview write (keeps same object identity)
        try:
            if self.size > 0 and getattr(self, "_mv", None) is not None:
                mv = self._mv
                # try to write using slice assignment (should be in-place)
                mv[:] = b"\x00" * len(mv)
                return
        except Exception as e:
            logger.debug("memoryview slice zero failed: %s", e)

        # Very slow but reliable fallback: byte-by-byte
        try:
            if getattr(self, "_mv", None) is not None:
                mv = self._mv
                for i in range(len(mv)):
                    mv[i] = 0
        except Exception:
            # Nothing more to do; best-effort only
            logger.error("SecureMemory: final zero fallback failed", exc_info=True)
            
    # --- Close / free ---
    def close(self) -> None:
        if self._closed:
            return

        # Zero first (tests expect memory visible as zero after zero/close)
        try:
            self.zero()
        except Exception:
            pass

        # If libsodium was used, try to unlock and free
        if self._use_sodium:
            try:
                if getattr(_sodium, "sodium_munlock", None):
                    try:
                        _sodium.sodium_munlock(self._ptr, self.size)
                    except Exception:
                        pass
                _sodium.sodium_free(self._ptr)
            except Exception:
                logger.debug("sodium_free/sodium_munlock failed (best-effort)")

            # release memoryview if present
            try:
                self._mv.release()
            except Exception:
                pass

            self._mv = None
            self._ptr = None
            self._use_sodium = False

        else:
            # fallback cleanup
            if self._fallback is not None:
                try:
                    self._fallback.close()
                except Exception:
                    pass
                self._fallback = None
            try:
                # release memoryview if not already
                if getattr(self, "_mv", None) is not None:
                    self._mv.release()
            except Exception:
                pass
            self._mv = None

        self._closed = True

    # Context manager
    def __enter__(self) -> "SecureMemory":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    # Convenience factories
    @classmethod
    def alloc(cls, size: int) -> "SecureMemory":
        return cls(size)

    @classmethod
    def from_bytes(cls, data: bytes) -> "SecureMemory":
        sm = cls(len(data))
        if len(data):
            sm.write(data, 0)
        return sm


# ---- Convenience helpers ----
def secure_alloc(size: int) -> _typing.ContextManager[SecureMemory]:
    class _Ctx:
        def __init__(self, n: int):
            self._n = n
            self._obj: SecureMemory | None = None

        def __enter__(self):
            self._obj = SecureMemory.alloc(self._n)
            return self._obj

        def __exit__(self, typ, exc, tb):
            if self._obj is not None:
                self._obj.close()
            self._obj = None

    return _Ctx(size)


def secret_bytes(data: bytes) -> SecureMemory:
    return SecureMemory.from_bytes(data)

