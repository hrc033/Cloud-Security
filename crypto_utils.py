from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # WARNING: Insecure for real use
    )

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_private_key(private_key_pem):
    return serialization.load_pem_private_key(
        private_key_pem,
        password=None, # WARNING: Insecure for real use
        backend=default_backend()
    )

def deserialize_public_key(public_key_pem):
    return serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

def encrypt_file(file_path, public_key):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        symmetric_key = os.urandom(32)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return iv, encrypted_symmetric_key, ciphertext
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None, None, None
    except Exception as e:
        print(f"Encryption error: {e}")
        return None, None, None

def decrypt_file(iv, encrypted_symmetric_key, ciphertext, private_key):
    try:
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

if __name__ == "__main__":
    private_key, public_key = generate_rsa_key_pair()
    private_pem = serialize_private_key(private_key)
    public_pem = serialize_public_key(public_key)
    print("RSA Key Pair Generated (for demonstration purposes only - secure storage needed)")
    print(f"Public Key:\n{public_pem.decode()}")
    print(f"Private Key:\n{private_pem.decode()}")