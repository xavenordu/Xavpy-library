from crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key

# Generate ephemeral key
key = CryptoKey.generate()

# Encrypt some sensitive data
data = b"super-secret-data"
ciphertext = encrypt_data(data, key)

# Decrypt
assert decrypt_data(ciphertext, key) == data

# Erase key for instant secure deletion
cryptographic_erase_key(key)
