# SecureWipe

High-assurance secure deletion, secure memory handling and cryptographic erasure for Python.

SecureWipe provides a modern, cross-platform suite of primitives for handling sensitive data safely.
It is designed for applications that require defense-in-depth: password managers, HSM glue code, data-at-rest protection, secure messaging and high-security Python systems.

It includes:

* Locked, zeroizable RAM (SecureMemory)
* Secure file wiping (multi-pass overwrite, free-space wiping)
* Cryptographic erasure (destroy a key → destroy the data)
* AES-GCM authenticated encryption helpers
* Secure temporary sessions (auto-delete on exit)

---

## Installation

```bash
pip install securewipe
```

---

# Overview of Protection Layers

SecureWipe implements five protection layers:

1. **Secure Memory**
   * Explicitly zeroizable buffers
   * Locked RAM (non-swappable when libsodium is available)
   * Safe handling for sensitive in-process secrets
   * Guaranteed wipe on .close() or context exit

3. **File Wiping**

   * Multi-pass secure deletion: random or fixed patterns (`secure_delete()`).
   * Full overwrite of file contents before unlinking
   * Free-space wiping (`wipe_free_space()`) to overwrite unallocated disk blocks.
   * Symlink-aware deletion controls

4. **Cryptographic Erasure**

   * AES-GCM encryption with authenticated metadata (`CryptoKey`).
   * `CryptoKey` objects that can be destroyed in memory
   * Destroy the key → all encrypted data irreversibly lost.
   * Designed for SSDs, COW filesystems, and other overwrite-hostile storage

5. **Secure Temporary Sessions**

   * `SecureSession` tracks temporary files, memory regions and secrets.
   * Automatically zeroes memory and deletes files on exit.
   * Ideal for one-shot secure operations

6. **OS-Level Erase Wrappers (Advanced)**

   * Interfaces for: hdparm, NVMe Secure Erase, APFS diskutil, BitLocker
   * Extremely dangerous and destructive if misused — disabled by default
   * Intended for expert operators only

---

# Quick Examples

## Cryptography Module

### Generate Key, Encrypt, and Cryptographically Erase

```python
from securewipe.crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key
from securewipe.utils import secure_clear

key = CryptoKey.generate(32)

with open("secret.txt", "rb") as f:
    plaintext = bytearray(f.read())

ct = encrypt_data(plaintext, key)

with open("secret.enc", "wb") as f:
    f.write(ct.nonce + ct.ciphertext)

secure_clear(plaintext)

recovered = decrypt_data(ct, key)
print("Recovered:", recovered.decode())

cryptographic_erase_key(key)
```

### Encrypt/Decrypt with AAD

```python
key = CryptoKey.generate()
pt = b"SENSITIVE-DATA"
aad = b"context-info"

ct = encrypt_data(pt, key, associated_data=aad)
recovered = decrypt_data(ct, key, associated_data=aad)
print(recovered)
```

---

## Secure Memory

```python
from securewipe.memory import SecureMemory, secret_bytes

s = SecureMemory.alloc(32)
s.write(b"supersecret")
print(s.read(11))
s.zero()
s.close()

sec = secret_bytes(b"topsecret")
print(sec.read(9))
sec.close()
```

---

## File Wiping

```python
from securewipe.file import secure_delete, wipe_free_space

secure_delete("secret.txt", passes=3, pattern="random")
wipe_free_space("/tmp", dry_run=True)
```

---

## Secure Session

```python
from securewipe.session import SecureSession

with SecureSession() as session:
    temp_file = session.create_temp_file(".txt")
    secret = session.create_secret(b"password123")

    with open(temp_file, "wb") as f:
        f.write(secret.get_bytes())
# On exit: memory zeroed, temp files deleted
```


---

# Limitations & Security Notes

## Cross-Platform Notes

| Feature                        | POSIX (Linux/macOS)                            | Windows                                                                        |
| ------------------------------ | ---------------------------------------------- | ------------------------------------------------------------------------------ |
| Symlink Handling               | Fully supported; `follow_symlinks` honored     | Some behaviors differ; tests skipped where behavior differs                    |
| Sparse File Detection          | Heuristics applied                             | Sparse heuristics differ; warnings may differ                                  |
| `chmod(0)` Permission Model | Enforced; deletion may raise `FileAccessError` | Behavior differs; some tests skipped                                           |
| SecureMemory Zeroing           | Zeroing observable in tests                    | Observing zeroing is unreliable due to Python memory copies and OS protections |
| Memory Locking          | `mlock` available (libsodium recommended)                    | `VirtualLock` less effective; libsodium strongly preferred|


* **Python Object Copies:** Immutable objects (`bytes`, `str`) cannot be zeroed. Prefer `bytearray` or `memoryview`.
* **Libsodium Recommended:** Provides guarded pages and secure memory locking. Fallback works but less secure.
* **Windows Memory Locking:** Pages cannot be made non-swappable without libsodium.
* **Garbage Collector Timing:** Python may temporarily retain buffers in RAM.
* **System Privileges:** Some OSes limit locked memory usage (e.g., `ulimit -l` on Linux).
* **File System Limitations:** Overwriting may not fully erase data on COW filesystems (btrfs, ZFS, snapshots) or SSDs. Consider crypto-erase.
* **OS-Level Erase:** `os_erase` functions are dangerous; use manually only with full understanding.


**Important Notes:**
SecureWipe improves security but cannot defeat OS-level guarantee gaps or Python’s memory model. Important limitations:

**Python Memory Model**
* Immutable types (bytes, str) cannot be zeroed.
* Some objects may be copied by Python internally.
* Use `bytearray` and `memoryview` for sensitive data.

**Libsodium Recommended**
* Libsodium Recommended
* Enables non-swappable memory
* Protects against overreads/overwrites

**Filesystem Constraints**
* SSDs, APFS/ZFS snapshots, btrfs COW, and journaling FSes may retain pre-image data.
* Free-space wiping mitigates but does not guarantee full erasure.
* For absolute erasure → cryptographic erase.

**Garbage Collection**
* Python may temporarily retain freed buffers before reuse.

**OS-Level Erase**
* Commands like hdparm and NVMe secure erase can brick disks.
* Disabled by default; require explicit opt-in.

**Always zero and close secrets**
* Use context managers or .close() to guarantee cleanup.

---

# Testing

```bash
pytest
```

Some tests skip on Windows due to OS Differences.

---

# License

MIT License — free for commercial, open-source, academic, and integrated use.

