import os
import sys
import pytest
from hypothesis import given, strategies as st, assume

from securewipe.memory import (
    SecureMemory,
    secure_alloc,
    secret_bytes,
    SecureMemoryClosed,
)

# ---------------------------------------------------------------------------
# Normal behavior tests
# ---------------------------------------------------------------------------

def test_secure_memory_write_and_zero():
    s = SecureMemory.alloc(32)
    try:
        s.write(b"hello-world", 0)
        assert s.read(11) == b"hello-world"

        s.zero()
        # On Windows, we cannot reliably observe zeroed memory
        if sys.platform != "win32":
            cleared = s.read(32)
            assert all(b == 0 for b in cleared)
    finally:
        s.close()
    assert s._closed


def test_secure_alloc_context_manager():
    with secure_alloc(16) as s:
        s.write(b"password123", 0)
        assert s.read(11) == b"password123"

    assert s._closed
    with pytest.raises(SecureMemoryClosed):
        s.write(b"x")
    with pytest.raises(SecureMemoryClosed):
        s.read(1)


def test_secure_memory_from_bytes_and_secret_bytes():
    data = b"supersecret"
    s1 = SecureMemory.from_bytes(data)
    assert s1._mv.tobytes() == data
    s1.close()

    s2 = secret_bytes(data)
    assert s2._mv.tobytes() == data
    s2.close()


def test_secure_memory_write_read_bounds():
    s = SecureMemory.alloc(8)
    with pytest.raises(ValueError):
        s.write(b"toolong", 2)
    with pytest.raises(ValueError):
        s.read(10)
    s.close()


def test_secure_memory_closed_exception():
    s = SecureMemory.alloc(8)
    s.close()
    with pytest.raises(SecureMemoryClosed):
        s.write(b"x")
    with pytest.raises(SecureMemoryClosed):
        s.read(1)


def test_secure_memory_zero_after_close():
    s = SecureMemory.alloc(8)
    s.write(b"abcd", 0)
    s.close()
    s.zero()
    assert s._closed


def test_secure_memory_multiple_allocations():
    buffers = [SecureMemory.alloc(16) for _ in range(3)]
    for i, b in enumerate(buffers):
        b.write(bytes([i]*16))
    for i, b in enumerate(buffers):
        assert b._mv.tobytes() == bytes([i]*16)
        b.close()
        assert b._closed


def test_secure_memory_partial_read_write():
    s = SecureMemory.alloc(16)
    s.write(b"12345678", offset=4)
    assert s._mv[4:8].tobytes() == b"1234"
    s.close()


# ---------------------------------------------------------------------------
# Hypothesis fuzz tests
# ---------------------------------------------------------------------------

@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=1024))
def test_secure_memory_write_read_fuzz(data):
    s = SecureMemory.alloc(len(data))
    try:
        s.write(data)
        # Directly inspect internal buffer
        assert s._mv.tobytes() == data
    finally:
        s.close()
    with pytest.raises(SecureMemoryClosed):
        s.read(1)


@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=1024))
def test_secure_memory_from_bytes_fuzz(data):
    s = secret_bytes(data)
    assert s._mv.tobytes() == data
    s.close()
    with pytest.raises(SecureMemoryClosed):
        s.write(b"x")


@pytest.mark.fuzz
@given(
    size=st.integers(min_value=1, max_value=1024),
    offset=st.integers(min_value=0, max_value=1023),
    data=st.binary(min_size=0, max_size=256)
)
def test_secure_memory_partial_write_read_fuzz(size, offset, data):
    assume(offset + len(data) <= size)
    s = SecureMemory.alloc(size)
    try:
        s.write(data, offset=offset)
        # Inspect internal memory directly
        assert s._mv[offset:offset+len(data)].tobytes() == data
    finally:
        s.close()


@pytest.mark.fuzz
@pytest.mark.skipif(sys.platform == "win32", reason="SecureMemory zeroing observation unreliable on Windows")
@given(data=st.binary(min_size=1, max_size=1024))
def test_secure_memory_zero_fuzz(data):
    s = SecureMemory.alloc(len(data))
    try:
        s.write(data)
        s.zero()
        # Check in-place zeroing of internal buffer
        assert all(b == 0 for b in s._mv)
    finally:
        s.close()
    with pytest.raises(SecureMemoryClosed):
        s.read(1)
