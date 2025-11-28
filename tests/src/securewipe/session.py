"""
securewipe.session
------------------

High-level context manager for secure sessions:
- All temporary files created inside are shredded on exit
- All secrets allocated inside are in secure memory
- Buffers wiped on error/exception
"""

from __future__ import annotations

import tempfile
import os
from pathlib import Path
from contextlib import contextmanager
import logging

from .file import secure_delete
from .memory import SecureMemory

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

class SecureSession:
    """
    Context manager for a secure session.
    Tracks temporary files and secure memory allocations.
    """

    def __init__(self):
        self._temp_files: list[Path] = []
        self._secrets: list[SecureMemory] = []

    def create_temp_file(self, suffix: str = "", prefix: str = "tmp", dir: str | None = None) -> Path:
        """
        Create a temporary file and track it for secure deletion on exit.
        File permissions are restricted (0600) for security.
        """
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
        os.fchmod(fd, 0o600)  # restrict permissions to owner read/write
        os.close(fd)  # Close immediately; user can open manually
        p = Path(path)
        self._temp_files.append(p)
        logger.debug("Created temporary file %s with 0600 permissions", p)
        return p

    def create_secret(self, data: bytes) -> SecureMemory:
        """
        Allocate a secure memory buffer and track it for cleanup.
        """
        sec = SecureMemory.from_bytes(data)
        self._secrets.append(sec)
        logger.debug("Allocated SecureMemory of size %d bytes", len(data))
        return sec

    def __enter__(self) -> SecureSession:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Wipe memory first
        for sec in self._secrets:
            try:
                sec.close()
                logger.debug("SecureMemory buffer closed and zeroed")
            except Exception as e:
                logger.warning("Failed to close SecureMemory buffer: %s", e)
        self._secrets.clear()

        # Shred temp files
        for path in self._temp_files:
            try:
                secure_delete(str(path), passes=3)
                logger.debug("Temporary file %s securely deleted", path)
            except Exception as e:
                logger.warning("Failed to securely delete temporary file %s: %s", path, e)
        self._temp_files.clear()


@contextmanager
def secure_session() -> SecureSession:
    """
    Context manager for a secure session.

    Usage:
        with secure_session() as sess:
            tmp = sess.create_temp_file()
            secret = sess.create_secret(b"my secret data")
    """
    sess = SecureSession()
    try:
        yield sess
    finally:
        sess.__exit__(None, None, None)
