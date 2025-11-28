import os
from random import randint
from securewipe.crypto import CryptoKey, encrypt_data, decrypt_data, cryptographic_erase_key

def fuzz_test_decrypt(key: CryptoKey, runs: int = 1000):
    """
    Fuzz-test decrypt_data() with random invalid CipherText inputs.
    
    Args:
        key: CryptoKey used for decryption
        runs: number of fuzz iterations
    """
    from securewipe.crypto import CipherText, decrypt_data

    failures = 0

    for i in range(runs):
        # Random nonce length between 0 and 20
        nonce_len = randint(0, 20)
        nonce = os.urandom(nonce_len)

        # Random ciphertext length between 0 and 50
        ct_len = randint(0, 50)
        ciphertext = os.urandom(ct_len)

        ct = CipherText(nonce=nonce, ciphertext=ciphertext)

        try:
            decrypt_data(ct, key)
        except ValueError:
            # Expected outcome
            failures += 1
        except Exception as e:
            print(f"Unexpected exception type on run {i}: {type(e)}")
            raise

    print(f"Fuzz test complete: {failures}/{runs} invalid inputs correctly failed.")

# Example usage:
key = CryptoKey.generate()
fuzz_test_decrypt(key)
