
# securewipe

**Securewipe** is a Python library for secure data deletion and in-memory secret handling.  
It provides **robust file shredding**, **secure memory allocation**, **cryptographic erasure**, and a **secure session manager** for temporary sensitive operations.

---

## Features

### 1. Secure File Deletion

Best-effort secure file deletion utilities:

- Overwrite files multiple times with random bytes and optional zeros
- Rename files before deletion to obscure metadata
- Wipe free space (optional)
- Warns about Copy-on-Write (COW) filesystems

```python
from securewipe.file import secure_delete, wipe_free_space

# Securely delete a file
secure_delete("secret.txt", passes=3)

# Wipe free space under a directory
wipe_free_space("/tmp")
```

### 2. Secure Memory Handling

Store sensitive data in **locked, non-swappable memory**:

```python
from securewipe.memory import SecureMemory

secret = SecureMemory.from_bytes(b"my-password")
print(secret.get_bytes())

# Zero memory when done
secret.close()
```

Supports optional **PyNaCl/libsodium** for enhanced security.

### 3. Cryptographic Erasure

Instantly erase encrypted data by destroying its key:

```python
from securewipe.crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key

# Generate a key
key = CryptoKey.generate()

# Encrypt data
data = b"super-secret-data"
ciphertext = encrypt_data(data, key)

# Decrypt
assert decrypt_data(ciphertext, key) == data

# Destroy key for instant cryptographic erasure
cryptographic_erase_key(key)
```

- Works on SSDs and Copy-on-Write filesystems
- Fast and reliable

### 4. OS-Level Secure Erase (Advanced)

Wrappers for expert users to trigger **native secure erase tools**:

```python
from securewipe import linux_hdparm_secure_erase, macos_diskutil_secure_erase

# WARNING: Dangerous operations — must be run manually and with caution
# linux_hdparm_secure_erase("/dev/sdb")
# macos_diskutil_secure_erase("/dev/disk2", level=1)
```

Supports:

- Linux: `hdparm`, `nvme`
- macOS: `diskutil secureErase`
- Windows: BitLocker key removal

> ⚠️ These operations are destructive. Always confirm devices and run as root/admin.

### 5. Secure Session Manager

Context manager for temporary sensitive data:

```python
from securewipe.session import SecureSession

with SecureSession() as session:
    key = session.create_secret(b"temporary-key")
    session.write_temp_file("temp.txt", b"top-secret-data")
# All temporary files and secrets are automatically wiped on exit
```

- All buffers and temporary files are erased on exit
- Ensures memory and file security even if exceptions occur

---

## Installation

```bash
# Core library
pip install securewipe

# Optional libsodium support
pip install securewipe[crypto]
```

## Supported Python Versions

- Python 3.8+
- Linux, macOS, Windows

---

## 🔒 Limitations & Important Notes

**Python object copies**

- Operations such as `get_bytes()` or returning raw Python bytes will create copies on the Python heap, which cannot be securely zeroed by Python code.
- If you require the highest assurance, avoid exposing secrets as Python bytes or strings.

**Libsodium strongly recommended**

For best security, install libsodium on the target system. Libsodium offers:

- `sodium_malloc()` / guarded pages
- `sodium_mlock()` / locked memory
- Hardened, zero-ing allocators

Typical installation on Linux:

```bash
sudo apt install libsodium23 libsodium-dev
```

or your distro’s equivalent packages (`yum`, `apk`, `brew`, etc.).

**Windows mlock limitations**

- The fallback mlock strategy is POSIX-only.
- True mlock is not available in the same form.
- A best-effort fallback allocator is used.
- Installing libsodium still significantly improves security.

**Garbage collector timing**

Even when using secure in-memory buffers, Python’s garbage collector may retain temporary copies made by internal operations or other libraries. To reduce exposure:

- Avoid creating temporary strings/bytes containing secrets
- Work with secure buffers directly
- Minimize copies and intermediate transformations

**System privileges**

Using mlock (or libsodium’s locked memory) may require:

- Elevated privileges
- Adjusted system limits (e.g., `ulimit -l` on Linux)
- Check system memory locking limits before relying on these features.

---

## License

MIT License © Ordu Stephen Chinedu

## Links

- **Homepage:** [https://github.com/yourname/securewipe](https://github.com/yourname/securewipe)  
- **Documentation:** [https://github.com/yourname/securewipe](https://github.com/yourname/securewipe)  
- **Repository:** [https://github.com/yourname/securewipe](https://github.com/yourname/securewipe)
