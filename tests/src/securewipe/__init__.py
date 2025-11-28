"""
SecureWipe: Secure file deletion, memory zeroization, and cryptographic erasure tools.
"""

from .file import secure_delete, wipe_free_space
from .memory import SecureMemory, secure_alloc, secret_bytes
from .crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key
from .session import secure_session
from .utils import secure_compare, secure_clear
from .os_erase import (
    linux_hdparm_secure_erase,
    linux_nvme_secure_erase,
    macos_diskutil_secure_erase,
    windows_bitlocker_destroy_volume_keys,
)

__all__ = ["secure_delete", 
                "wipe_free_space", 
                "SecureMemory", 
                "secure_alloc", 
                "secret_bytes",
                "linux_hdparm_secure_erase",
                "linux_nvme_secure_erase",
                "macos_diskutil_secure_erase",
                "windows_bitlocker_destroy_volume_keys",
                "CryptoKey",
                "encrypt_data",
                "decrypt_data",
                "cryptographic_erase_key"
                ]

__all__.extend(["encrypt", "decrypt", "destroy_key", "secure_session"])
__version__ = "1.0.0"
__author__ = "Ordu Stephen Chinedu"
__license__ = "MIT"
__copyright__ = "2024 Ordu Stephen Chinedu"

