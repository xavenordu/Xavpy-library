"""
securewipe._sodium
------------------

Shim for libsodium allocation functions.

- Provides: sodium_init, sodium_malloc, sodium_free, sodium_mlock, sodium_munlock, sodium_memzero
- If libsodium unavailable, provides fallback (POSIX mlock or Windows VirtualLock).

Notes:
- Fallback does NOT provide guard pages or prevent swapping.
- On Windows, fallback uses VirtualLock / VirtualUnlock if possible.
- All functions are best-effort; failure to lock memory or zero it is logged but not fatal.
"""

from __future__ import annotations
import ctypes
import ctypes.util
import os
import logging
from typing import Optional, Tuple, Union

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_libsodium = None
_have_sodium = False
_libc = None
_have_mlock = False

c_void_p = ctypes.c_void_p
c_size_t = ctypes.c_size_t

def _try_load_libsodium() -> Optional[ctypes.CDLL]:
    for name in ("sodium", "libsodium"):
        libname = ctypes.util.find_library(name)
        if libname:
            try:
                return ctypes.CDLL(libname)
            except Exception:
                pass
    return None

def _try_load_libc() -> Optional[ctypes.CDLL]:
    if os.name == "posix":
        for candidate in ("c", "libc.so.6", "libc.dylib"):
            try:
                return ctypes.CDLL(ctypes.util.find_library(candidate) or candidate)
            except Exception:
                continue
    return None

# Load libsodium if present
_libsodium = _try_load_libsodium()
if _libsodium:
    try:
        if hasattr(_libsodium, "sodium_init"):
            _libsodium.sodium_init.restype = ctypes.c_int
            _libsodium.sodium_init()
        _have_sodium = True
    except Exception:
        _have_sodium = False

# Load libc for mlock/munlock fallback on POSIX
if not _have_sodium and os.name != "nt":
    _libc = _try_load_libc()
    if _libc:
        try:
            _libc.mlock.argtypes = (c_void_p, c_size_t)
            _libc.mlock.restype = ctypes.c_int
            _libc.munlock.argtypes = (c_void_p, c_size_t)
            _libc.munlock.restype = ctypes.c_int
            _have_mlock = True
        except Exception:
            _have_mlock = False

# --- Public API -----------------------------------------------------------
def have_libsodium() -> bool:
    return _have_sodium

if _have_sodium:
    sodium_malloc = _libsodium.sodium_malloc
    sodium_malloc.argtypes = (c_size_t,)
    sodium_malloc.restype = c_void_p

    sodium_free = _libsodium.sodium_free
    sodium_free.argtypes = (c_void_p,)
    sodium_free.restype = None

    sodium_mlock = getattr(_libsodium, "sodium_mlock", None)
    if sodium_mlock:
        sodium_mlock.argtypes = (c_void_p, c_size_t)
        sodium_mlock.restype = ctypes.c_int

    sodium_munlock = getattr(_libsodium, "sodium_munlock", None)
    if sodium_munlock:
        sodium_munlock.argtypes = (c_void_p, c_size_t)
        sodium_munlock.restype = ctypes.c_int

    sodium_memzero = _libsodium.sodium_memzero
    sodium_memzero.argtypes = (c_void_p, c_size_t)
    sodium_memzero.restype = None

    def sodium_alloc_buf(size: int) -> Tuple[c_void_p, memoryview]:
        ptr = sodium_malloc(size)
        if not ptr:
            raise MemoryError("sodium_malloc failed")
        buf_type = ctypes.POINTER(ctypes.c_ubyte * size)
        cbuf = ctypes.cast(ptr, buf_type).contents
        mv = memoryview(bytearray(cbuf))
        return ptr, mv

else:
    # --- Fallback implementations ---
    import sys

    def sodium_memzero(ptr: Union[int, ctypes._CData], size: int) -> None:
        try:
            if isinstance(ptr, int):
                ctypes.memset(ptr, 0, size)
            else:
                mv = memoryview(ptr)
                mv[:size] = b"\x00" * size
        except Exception as e:
            logger.debug("Fallback sodium_memzero failed: %s", e)

    def sodium_mlock(ptr: Union[int, ctypes._CData], size: int) -> int:
        if os.name == "nt":
            try:
                kernel32 = ctypes.windll.kernel32
                addr = ctypes.addressof(ptr) if not isinstance(ptr, int) else ptr
                return kernel32.VirtualLock(addr, size)
            except Exception as e:
                logger.debug("Fallback VirtualLock failed: %s", e)
                return 0
        elif _have_mlock:
            addr = ctypes.addressof(ptr) if not isinstance(ptr, int) else ptr
            return _libc.mlock(addr, size)
        return -1

    def sodium_munlock(ptr: Union[int, ctypes._CData], size: int) -> int:
        if os.name == "nt":
            try:
                kernel32 = ctypes.windll.kernel32
                addr = ctypes.addressof(ptr) if not isinstance(ptr, int) else ptr
                return kernel32.VirtualUnlock(addr, size)
            except Exception as e:
                logger.debug("Fallback VirtualUnlock failed: %s", e)
                return 0
        elif _have_mlock:
            addr = ctypes.addressof(ptr) if not isinstance(ptr, int) else ptr
            return _libc.munlock(addr, size)
        return -1

    def sodium_malloc(size: int) -> ctypes._CData:
        return ctypes.create_string_buffer(size)

    def sodium_free(buf: ctypes._CData) -> None:
        try:
            mv = memoryview(buf)
            mv[:] = b"\x00" * len(mv)
        except Exception as e:
            logger.debug("Fallback sodium_free zero failed: %s", e)
        # rely on Python GC

    def sodium_alloc_buf(size: int) -> Tuple[ctypes._CData, memoryview]:
        buf = ctypes.create_string_buffer(size)
        mv = memoryview(buf)
        return buf, mv

__all__ = [
    "have_libsodium",
    "sodium_malloc",
    "sodium_free",
    "sodium_mlock",
    "sodium_munlock",
    "sodium_memzero",
    "sodium_alloc_buf",
]
