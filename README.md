# SecureWipe

High-assurance secure deletion and secure memory handling for Python.

---

## Features

* Cryptographic erasure utilities (`CryptoKey`, `encrypt_data`, `decrypt_data`, `cryptographic_erase_key`)
* High-level `SecureMemory` API with locked memory and explicit zeroing
* File wiping (`secure_delete`, `wipe_free_space`) with customizable patterns
* Cross-platform support for Linux, macOS, and Windows

---

## Installation

```bash
pip install securewipe
```

---

## Usage Examples

### Secure Memory

```python
from securewipe.memory import SecureMemory, secret_bytes

# Allocate 32 bytes of secure memory
s = SecureMemory.alloc(32)
s.write(b"supersecret")
print(s.read(11))  # b'supersecret'
s.zero()  # zero memory
s.close()

# Using secret_bytes convenience helper
sec = secret_bytes(b"topsecret")
print(sec.read(len(b"topsecret")))
sec.close()
```

### File Deletion

```python
from securewipe.file import secure_delete

# Securely delete a file
secure_delete("secret.txt", passes=3, pattern="random", dry_run=False)

# Wipe free space in a directory
from securewipe.file import wipe_free_space
wipe_free_space("/tmp", dry_run=True)
```

### Secure Session

```python
from securewipe.session import SecureSession

with SecureSession() as session:
    temp_file = session.create_temp_file(suffix=".txt")
    secret = session.create_secret(b"password123")
    with open(temp_file, "wb") as f:
        f.write(secret.get_bytes())
# Temp files are removed, secret memory zeroed automatically
```

---

## Limitations & Cross-Platform Notes

| Feature                        | POSIX (Linux/macOS)                            | Windows                                                                        |
| ------------------------------ | ---------------------------------------------- | ------------------------------------------------------------------------------ |
| Symlink Handling               | Fully supported; `follow_symlinks` honored     | Some behaviors differ; tests skipped where behavior differs                    |
| Sparse File Detection          | Heuristics applied                             | Sparse heuristics differ; warnings may differ                                  |
| `chmod(0)` & Permission Errors | Enforced; deletion may raise `FileAccessError` | Behavior differs; some tests skipped                                           |
| SecureMemory Zeroing           | Zeroing observable in tests                    | Observing zeroing is unreliable due to Python memory copies and OS protections |

**Important Notes:**

* Avoid exposing raw Python bytes from `SecureMemory` (`get_bytes()`), as Python copies cannot be securely zeroed.
* Always use the `close()` or context manager to guarantee memory zeroing.

---

## Testing

Run the full test suite with:

```bash
pytest
```

Some tests are skipped on Windows due to OS-specific behavior.
