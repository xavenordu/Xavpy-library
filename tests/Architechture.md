                      ┌───────────────────────────┐
                      │  OS / Firmware Level      │
                      │  Secure Erase (Expert)    │
                      │                           │
                      │ Linux: hdparm / nvme      │
                      │ macOS: diskutil secureErase│
                      │ Windows: BitLocker keys    │
                      └─────────────┬────────────┘
                                    │
                                    │ (full-disk / volume erase)
                                    ▼
                      ┌───────────────────────────┐
                      │  Cryptographic Erasure    │
                      │  (Instant secure wipe)    │
                      │                           │
                      │ - CryptoKey in SecureMemory│
                      │ - Destroy key -> all data │
                      │   encrypted by it is gone │
                      └─────────────┬────────────┘
                                    │
                                    │ (fast, reliable)
                                    ▼
                      ┌───────────────────────────┐
                      │  Secure File Deletion     │
                      │  (overwrite / shred)     │
                      │                           │
                      │ - secure_delete()         │
                      │ - wipe_free_space()       │
                      │ - COW / sparse detection │
                      │ - cross-platform (POSIX /│
                      │   Windows)               │
                      └─────────────┬────────────┘
                                    │
                                    │ (temporary files)
                                    ▼
                      ┌───────────────────────────┐
                      │  Secure Memory Handling   │
                      │  (High-value secret storage) │
                      │                           │
                      │ - SecureMemory class      │
                      │ - mlock / sodium_memzero  │
                      │ - auto-zero on close / GC │
                      │ - context manager support │
                      └─────────────┬────────────┘
                                    │
                                    │ (used inside sessions)
                                    ▼
                      ┌───────────────────────────┐
                      │  Secure Session Context   │
                      │  Manager (UX-friendly)    │
                      │                           │
                      │ - Tracks temp files &     │
                      │   secrets                 │
                      │ - Wipes memory & files on │
                      │   exit / exception        │
                      │ - High-level Python API   │
                      └───────────────────────────┘

Flow Notes

OS/Firmware Secure Erase

Only for expert users; destructive.

Eliminates all traces from the physical medium (SSD/HDD/volume).

Cryptographic Erasure

Immediate, reliable.

Only requires key destruction, avoids overwriting entire storage.

Secure File Deletion

Best-effort, platform-aware shredding.

Handles sparse files, COW filesystems, and free space wiping.

Secure Memory

Protects in-RAM secrets with locked memory.

Ensures zeroization on close or GC.

Secure Session

High-level user-friendly API.

Combines temporary files + secrets + automatic cleanup.

Ideal for app developers handling sensitive data safely without manual bookkeeping.