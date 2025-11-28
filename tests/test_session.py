import os
import warnings
import pytest
from pathlib import Path
from hypothesis import given, strategies as st

from securewipe.file import secure_delete, wipe_free_space, FileAccessError
from securewipe.utils import secure_compare
from securewipe.memory import SecureMemory, SecureMemoryClosed
from securewipe.session import SecureSession

# ---------------------------------------------------------------------------
# File Module Tests
# ---------------------------------------------------------------------------

def test_secure_delete_creates_no_file(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_bytes(b"super-secret-data")
    secure_delete(str(p), passes=2, pattern="random", dry_run=True)
    assert p.exists()

def test_secure_delete_removes_file(tmp_path):
    p = tmp_path / "secret2.txt"
    p.write_bytes(b"hello-world")
    secure_delete(str(p), passes=1, pattern="zeros", dry_run=False)
    assert not p.exists()

@pytest.mark.skipif(os.name == "nt", reason="Symlink behavior differs on Windows")
def test_secure_delete_symlink_not_followed(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("secret")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    secure_delete(str(link), dry_run=False)
    assert not link.exists()
    assert target.exists()

@pytest.mark.skipif(os.name == "nt", reason="Symlink behavior differs on Windows")
def test_secure_delete_follows_symlink(tmp_path):
    target = tmp_path / "real2.txt"
    target.write_text("supersecret")
    link = tmp_path / "link2.txt"
    link.symlink_to(target)
    secure_delete(str(link), follow_symlinks=True, dry_run=False)
    assert not target.exists()

@pytest.mark.skipif(os.name == "nt", reason="Sparse heuristic differs on Windows")
def test_secure_delete_sparse_warning(tmp_path):
    p = tmp_path / "sparse.bin"
    with open(p, "wb") as f:
        f.seek(10_000_000)
        f.write(b"\0")
    with warnings.catch_warnings(record=True):
        secure_delete(str(p), dry_run=True)
    assert p.exists()

def test_secure_delete_rename_failure(tmp_path, monkeypatch):
    p = tmp_path / "file.txt"
    p.write_text("abc123")
    def fake_replace(src, dst):
        raise OSError("simulated rename failure")
    monkeypatch.setattr(os, "replace", fake_replace)
    secure_delete(str(p), dry_run=False)
    assert not p.exists()

@pytest.mark.skipif(os.name == "nt", reason="chmod(0) behavior differs on Windows")
def test_secure_delete_permission_error(tmp_path):
    p = tmp_path / "locked.txt"
    p.write_text("cant touch this")
    p.chmod(0)
    with pytest.raises(FileAccessError):
        secure_delete(str(p), dry_run=False)

def test_wipe_free_space_dry(tmp_path):
    (tmp_path / "a").write_text("x")
    wipe_free_space(str(tmp_path), chunk_size=4096, dry_run=True)

def test_wipe_free_space_tempfile_removed_in_dry_run(tmp_path):
    wipe_free_space(str(tmp_path), dry_run=True)
    leftovers = list(tmp_path.glob(".wipe_*"))
    assert leftovers == []

def test_wipe_free_space_non_directory(tmp_path):
    file = tmp_path / "notadir"
    file.write_text("x")
    with pytest.raises(NotADirectoryError):
        wipe_free_space(str(file))

# ---------------------------------------------------------------------------
# Fuzz and Memory Tests
# ---------------------------------------------------------------------------

@pytest.mark.fuzz
@given(st.binary(), st.binary())
def test_secure_compare_fuzz(a, b):
    expected = (a == b)
    assert secure_compare(a, b) == expected

@pytest.mark.fuzz
@pytest.mark.skipif(os.name == "nt", reason="SecureMemory zeroing observation unreliable on Windows")
@given(st.binary(min_size=0, max_size=4096))
def test_secure_memory_wipe_fuzz(data):
    """Ensure SecureMemory always wipes correctly by checking internal buffer."""
    mem = SecureMemory(len(data))
    try:
        mem.write(data)
        mem.zero()
        assert all(b == 0 for b in mem._mv)
    finally:
        mem.close()

# ---------------------------------------------------------------------------
# SecureSession Tests
# ---------------------------------------------------------------------------

def test_secure_session_temp_file_cleanup():
    with SecureSession() as s:
        temp_file = s.create_temp_file(suffix=".txt")
        assert Path(temp_file).exists()
        with open(temp_file, "wb") as f:
            f.write(b"secret-data")
    # Temp file should be deleted on session exit
    assert not Path(temp_file).exists()

def test_secure_session_secret_memory_cleanup():
    secret_data = b"supersecret"
    with SecureSession() as s:
        sec = s.create_secret(secret_data)
        assert sec._mv.tobytes() == secret_data
    # Reading after session exit should raise
    with pytest.raises(SecureMemoryClosed):
        sec.read(1)

def test_secure_session_combined_usage():
    data = b"password123"
    with SecureSession() as s:
        temp_file = s.create_temp_file()
        secret = s.create_secret(data)
        with open(temp_file, "wb") as f:
            f.write(secret.get_bytes())
        assert Path(temp_file).exists()
    # Temp file deleted
    assert not Path(temp_file).exists()
    # Secret memory closed
    with pytest.raises(SecureMemoryClosed):
        secret.read(1)
