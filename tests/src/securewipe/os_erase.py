"""
securewipe.os_erase
-------------------

Wrappers for OS-level secure erase operations.

WARNING:
- These functions are extremely dangerous if used incorrectly.
- Do NOT call on your system drive unless you are absolutely certain.
- Must be run with appropriate privileges (root / admin).
- Always double-check device paths before proceeding.
- These functions are mostly placeholders; the user must implement the actual commands
  carefully and manually confirm destructive operations.

Intended for advanced users and system administrators.
"""

from __future__ import annotations
import subprocess
import shutil
import platform
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

_SYSTEM = platform.system()

# ------------------- Linux -------------------

def linux_hdparm_secure_erase(device_path: str) -> None:
    """
    Trigger a secure erase on a drive using hdparm.

    Requires root privileges.
    WARNING: This will wipe the entire drive irreversibly!

    Args:
        device_path: Raw device path, e.g., /dev/sda

    Raises:
        RuntimeError: if not on Linux
        ValueError: if device_path invalid
        NotImplementedError: instructs user to implement manually
    """
    if _SYSTEM != "Linux":
        raise RuntimeError("This function only runs on Linux")
    if not shutil.which("hdparm"):
        raise RuntimeError("hdparm not found on system")
    if not device_path.startswith("/dev/"):
        raise ValueError("device_path must be a raw device like /dev/sda")

    logger.warning(
        "!!! DANGER !!! This will erase all data on %s. "
        "You must manually set a temporary password and confirm execution.",
        device_path
    )
    # Example manual commands:
    # subprocess.run(["hdparm", "--user-master", "u", "--security-set-pass", "PASSWORD", device_path], check=True)
    # subprocess.run(["hdparm", "--user-master", "u", "--security-erase", "PASSWORD", device_path], check=True)
    raise NotImplementedError("Secure erase requires manual password setup. See docstring.")


def linux_nvme_secure_erase(device_path: str) -> None:
    """
    Trigger NVMe secure erase using the 'nvme' CLI.

    WARNING: This will wipe the entire drive irreversibly!

    Args:
        device_path: Raw NVMe device, e.g., /dev/nvme0n1

    Raises:
        RuntimeError: if not on Linux
        ValueError: if device_path invalid
        NotImplementedError: instructs user to implement manually
    """
    if _SYSTEM != "Linux":
        raise RuntimeError("This function only runs on Linux")
    if not shutil.which("nvme"):
        raise RuntimeError("nvme CLI not found")
    if not device_path.startswith("/dev/"):
        raise ValueError("device_path must be a raw NVMe device like /dev/nvme0n1")

    logger.warning(
        "!!! DANGER !!! This will erase all data on %s. Use 'nvme format --ses=1' manually.",
        device_path
    )
    raise NotImplementedError("NVMe secure erase is dangerous. Implement manually with nvme CLI.")


# ------------------- macOS -------------------

def macos_diskutil_secure_erase(disk: str, level: int = 0) -> None:
    """
    Perform secure erase using macOS diskutil.

    WARNING: This will wipe the disk irreversibly!

    Args:
        disk: Raw disk, e.g., /dev/diskX
        level: 0=single pass zeros, 1=7-pass, 2=35-pass

    Raises:
        RuntimeError: if not on macOS
        NotImplementedError: instructs user to confirm manually
    """
    if _SYSTEM != "Darwin":
        raise RuntimeError("This function only runs on macOS")
    if not shutil.which("diskutil"):
        raise RuntimeError("diskutil not found")

    logger.warning(
        "!!! DANGER !!! Secure erase of %s at level %d. Confirm manually before running.",
        disk, level
    )
    # Example manual command:
    # subprocess.run(["diskutil", "secureErase", str(level), disk], check=True)
    raise NotImplementedError(
        "Secure erase is dangerous; user must confirm disk and level manually."
    )


# ------------------- Windows -------------------

def windows_bitlocker_destroy_volume_keys(volume: str) -> None:
    """
    Remove BitLocker keys for the given volume.

    WARNING:
    - This effectively renders the encrypted volume inaccessible.
    - Requires admin privileges.

    Args:
        volume: Volume identifier, e.g., "C:"

    Raises:
        RuntimeError: if not on Windows
        NotImplementedError: instructs user to run manually
    """
    if _SYSTEM != "Windows":
        raise RuntimeError("This function only runs on Windows")
    if not shutil.which("manage-bde"):
        raise RuntimeError("manage-bde not found")

    logger.warning(
        "!!! DANGER !!! This will delete BitLocker keys for %s. Confirm manually before running.",
        volume
    )
    # Example manual command:
    # subprocess.run(["manage-bde", "-protectors", "-delete", volume], check=True)
    raise NotImplementedError(
        "BitLocker key destruction must be run manually with manage-bde."
    )
