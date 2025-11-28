"""
Device-level wipe: ATA Secure Erase / NVMe secure erase wrappers.
Requires administrative privileges.
"""

import subprocess

def secure_erase_ata(device: str):
    """Run ATA Secure Erase via hdparm."""
    subprocess.run(["hdparm", "--security-erase", "NULL", device], check=True)

def secure_erase_nvme(device: str):
    """Run NVMe Secure Erase."""
    subprocess.run(["nvme", "format", device, "--ses=1"], check=True)

def is_ata_device(device: str) -> bool:
    """Check if the device is an ATA device."""
    try:
        result = subprocess.run(["hdparm", "-I", device], capture_output=True, text=True)
        return "ATA" in result.stdout
    except Exception:
        return False