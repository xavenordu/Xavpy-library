import pytest
from securewipe.utils import secure_compare, secure_clear

def test_secure_compare_equal():
    a = b"secret123"
    b_ = b"secret123"
    assert secure_compare(a, b_) is True

def test_secure_compare_unequal():
    a = b"secret123"
    b_ = b"Secret123"
    assert secure_compare(a, b_) is False

def test_secure_compare_different_lengths():
    a = b"secret"
    b_ = b"secret123"
    assert secure_compare(a, b_) is False

def test_secure_clear_bytearray():
    data = bytearray(b"temporary")
    secure_clear(data)
    assert data == b"\x00" * len(data)

def test_secure_clear_memoryview():
    buf = bytearray(b"data")
    mv = memoryview(buf)
    secure_clear(mv)
    assert buf == b"\x00" * len(buf)

def test_secure_clear_invalid_type():
    with pytest.raises(TypeError):
        secure_clear(b"bytes")  # immutable bytes should raise
