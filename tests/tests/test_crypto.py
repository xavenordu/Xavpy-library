import pytest
from hypothesis import given, strategies as st, assume

from securewipe.crypto import (
    CryptoKey,
    encrypt_data,
    decrypt_data,
    cryptographic_erase_key,
    CipherText,
)
from securewipe.memory import SecureMemoryClosed

# ---------------------------------------------------------------------------
# ------------------------ Normal behavior tests ---------------------------
# ---------------------------------------------------------------------------

def test_crypto_key_generation():
    key = CryptoKey.generate()
    key_bytes = key.get_bytes()
    assert isinstance(key_bytes, bytes)
    assert len(key_bytes) == 32  # AES-256 default
    key.destroy()
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()

def test_crypto_key_invalid_length():
    with pytest.raises(ValueError):
        CryptoKey(b"short")
    with pytest.raises(ValueError):
        CryptoKey(b"x" * 17)

def test_crypto_key_invalid_type():
    with pytest.raises(TypeError):
        CryptoKey("not-bytes")

def test_encrypt_decrypt_buffer():
    key = CryptoKey.generate()
    data = b"top-secret-data"
    ct = encrypt_data(data, key)
    assert isinstance(ct, CipherText)
    plaintext = decrypt_data(ct, key)
    assert plaintext == data
    key.destroy()

def test_encrypt_decrypt_with_associated_data():
    key = CryptoKey.generate()
    data = b"confidential"
    aad = b"metadata"
    ct = encrypt_data(data, key, associated_data=aad)
    decrypted = decrypt_data(ct, key, associated_data=aad)
    assert decrypted == data
    key.destroy()

def test_decrypt_wrong_aad_fails():
    key = CryptoKey.generate()
    data = b"secret"
    ct = encrypt_data(data, key, associated_data=b"aad1")
    with pytest.raises(Exception):
        decrypt_data(ct, key, associated_data=b"aad2")
    key.destroy()

def test_decrypt_invalid_ct_type():
    key = CryptoKey.generate()
    with pytest.raises(TypeError):
        decrypt_data(b"not-a-CipherText", key)
    key.destroy()

def test_decrypt_invalid_nonce_length():
    key = CryptoKey.generate()
    ct = CipherText(nonce=b"short", ciphertext=b"cipher")
    with pytest.raises(ValueError):
        decrypt_data(ct, key)
    key.destroy()

def test_cryptographic_erase_key():
    key = CryptoKey.generate()
    key_bytes_before = key.get_bytes()
    assert key_bytes_before != b"\x00" * 32
    cryptographic_erase_key(key)
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()

# ---------------------------------------------------------------------------
# ------------------------- Hypothesis fuzz tests ---------------------------
# ---------------------------------------------------------------------------

@pytest.mark.fuzz
@given(length=st.sampled_from([16, 24, 32]))
def test_crypto_key_generate_fuzz(length):
    key = CryptoKey.generate(length)
    key_bytes = key.get_bytes()
    assert isinstance(key_bytes, bytes)
    assert len(key_bytes) == length
    key.destroy()
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()

@pytest.mark.fuzz
@given(
    plaintext=st.binary(min_size=0, max_size=2048),
    aad=st.one_of(st.none(), st.binary(min_size=0, max_size=128))
)
def test_encrypt_decrypt_fuzz(plaintext, aad):
    key = CryptoKey.generate()
    ct = encrypt_data(plaintext, key, associated_data=aad)
    assert isinstance(ct, CipherText)
    decrypted = decrypt_data(ct, key, associated_data=aad)
    assert decrypted == plaintext
    key.destroy()
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()

@pytest.mark.fuzz
@given(length=st.sampled_from([16, 24, 32]))
def test_cryptographic_erase_key_fuzz(length):
    key = CryptoKey.generate(length)
    bytes_before = key.get_bytes()
    assert bytes_before != b"\x00" * length
    cryptographic_erase_key(key)
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()

@pytest.mark.fuzz
@given(
    plaintext=st.binary(min_size=1, max_size=1024),
    wrong_aad=st.binary(min_size=1, max_size=32)
)
def test_decrypt_wrong_aad_fuzz(plaintext, wrong_aad):
    key = CryptoKey.generate()
    ct = encrypt_data(plaintext, key, associated_data=None)
    with pytest.raises(Exception):
        decrypt_data(ct, key, associated_data=wrong_aad)
    key.destroy()
    with pytest.raises(SecureMemoryClosed):
        key.get_bytes()
def test_decrypt_invalid_ct_fuzz(plaintext):
    key =   CryptoKey.generate()
    with pytest.raises(TypeError):
        decrypt_data(b"invalid-ct", key)
