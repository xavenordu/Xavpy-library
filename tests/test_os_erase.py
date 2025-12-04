import sys
import pytest
from unittest.mock import patch, MagicMock
import platform

from zeroizepy import (
    linux_hdparm_secure_erase,
    linux_nvme_secure_erase,
    macos_diskutil_secure_erase,
    windows_bitlocker_destroy_volume_keys,
)

# ----------------- Linux tests -----------------

@pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
def test_linux_hdparm_secure_erase_validation(monkeypatch):
    # Patch shutil.which to simulate hdparm exists
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/sbin/hdparm")
    # Device path must start with /dev/
    with pytest.raises(ValueError):
        linux_hdparm_secure_erase("notadev")

    # Since actual implementation raises NotImplementedError
    with pytest.raises(NotImplementedError):
        linux_hdparm_secure_erase("/dev/sdb")

@pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
def test_linux_nvme_secure_erase_validation(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/sbin/nvme")
    with pytest.raises(ValueError):
        linux_nvme_secure_erase("sda0")
    with pytest.raises(NotImplementedError):
        linux_nvme_secure_erase("/dev/nvme0n1")

# ----------------- macOS tests -----------------

@pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
def test_macos_diskutil_secure_erase(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/sbin/diskutil")
    with pytest.raises(NotImplementedError):
        macos_diskutil_secure_erase("/dev/disk2", level=1)

# ----------------- Windows tests -----------------

@pytest.mark.skipif(platform.system() != "Windows", reason="Windows only")
def test_windows_bitlocker_destroy_volume_keys(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "C:\\Windows\\System32\\manage-bde.exe")
    with pytest.raises(NotImplementedError):
        windows_bitlocker_destroy_volume_keys("C:")

