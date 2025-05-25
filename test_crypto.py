from cryptography.hazmat.primitives.ciphers.algorithms import AESGCM

try:
    key = b'This is a 32-byte key'
    nonce = b'this is some iv'
    cipher = AESGCM(key)
    associated_data = b'this data is authenticated'
    plaintext = b'this is the message'
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
    print("AESGCM found and working.")
except AttributeError as e:
    print(f"Error: {e}")
except ImportError as e:
    print(f"Import Error: {e}")

import cryptography
print(f"Cryptography version: {cryptography.__version__}")