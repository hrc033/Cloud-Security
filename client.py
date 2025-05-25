import os
from crypto_utils import generate_rsa_key_pair, serialize_private_key, serialize_public_key, deserialize_public_key, encrypt_file, decrypt_file
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass  # For securely getting password input

SERVER_STORAGE_DIR = "server_files" # For simulation
KEYS_DIR = "user_keys"

def create_keys_directory():
    os.makedirs(KEYS_DIR, exist_ok=True)

def get_user_keys_path(user_id, filename):
    return os.path.join(KEYS_DIR, f"{user_id}_{filename}")

def generate_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_private_key(private_key_pem, password):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key, salt = generate_key_from_password(password)
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AESGCM(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(private_key_pem) + encryptor.finalize()
    return salt, iv, ciphertext

def decrypt_private_key(salt, iv, ciphertext, password):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key, _ = generate_key_from_password(password, salt)
    decryptor = Cipher(
        algorithms.AESGCM(key),
        modes.GCM(iv),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def register_user():
    user_id = input("Enter a username for registration: ")
    password = getpass.getpass("Enter a password for your private key: ")
    confirm_password = getpass.getpass("Confirm your password: ")
    if password != confirm_password:
        print("Passwords do not match.")
        return

    private_key, public_key = generate_rsa_key_pair()
    private_key_pem = serialize_private_key(private_key)
    public_key_pem = serialize_public_key(public_key)

    salt, iv, encrypted_private_key = encrypt_private_key(private_key_pem, password)

    create_keys_directory()
    with open(get_user_keys_path(user_id, "public_key.pem"), "wb") as f:
        f.write(public_key_pem)
    with open(get_user_keys_path(user_id, "private_key.enc"), "wb") as f:
        f.write(encrypted_private_key)
    with open(get_user_keys_path(user_id, "private_key.salt"), "wb") as f:
        f.write(salt)
    with open(get_user_keys_path(user_id, "private_key.iv"), "wb") as f:
        f.write(iv)

    print(f"User '{user_id}' registered. Public key and encrypted private key saved.")
    return user_id

def load_private_key(user_id, password):
    try:
        with open(get_user_keys_path(user_id, "private_key.enc"), "rb") as f:
            encrypted_private_key = f.read()
        with open(get_user_keys_path(user_id, "private_key.salt"), "rb") as f:
            salt = f.read()
        with open(get_user_keys_path(user_id, "private_key.iv"), "rb") as f:
            iv = f.read()

        decrypted_private_key_pem = decrypt_private_key(salt, iv, encrypted_private_key, password)
        from crypto_utils import deserialize_private_key
        private_key = deserialize_private_key(decrypted_private_key_pem)
        return private_key
    except FileNotFoundError:
        print("Error: User private key files not found.")
        return None
    except Exception as e:
        print(f"Error decrypting private key: {e}")
        return None

def load_public_key(user_id):
    try:
        with open(get_user_keys_path(user_id, "public_key.pem"), "rb") as f:
            public_key_pem = f.read()
        from crypto_utils import deserialize_public_key
        public_key = deserialize_public_key(public_key_pem)
        return public_key
    except FileNotFoundError:
        print("Error: User public key file not found.")
        return None

def upload_file(user_id, server_public_key):
    private_key = None
    while not private_key:
        password = getpass.getpass("Enter password to unlock your private key: ")
        private_key = load_private_key(user_id, password)
        if not private_key:
            print("Incorrect password or key file issue.")

    file_path = input("Enter the path of the file to upload: ")
    if not os.path.exists(file_path):
        print("Error: File not found.")
        return

    iv, encrypted_key, ciphertext = encrypt_file(file_path, server_public_key)
    if iv and encrypted_key and ciphertext:
        filename = os.path.basename(file_path)
        upload_path = os.path.join(SERVER_STORAGE_DIR, f"{user_id}_{filename}.encrypted")
        metadata = f"{iv.hex()}:{encrypted_key.hex()}"
        metadata_path = os.path.join(SERVER_STORAGE_DIR, f"{user_id}_{filename}.metadata")

        os.makedirs(SERVER_STORAGE_DIR, exist_ok=True)
        with open(upload_path, "wb") as f:
            f.write(ciphertext)
        with open(metadata_path, "w") as f:
            f.write(metadata)
        print(f"File '{filename}' uploaded and encrypted.")

def download_file(user_id, server_private_key):
    private_key = None
    while not private_key:
        password = getpass.getpass("Enter password to unlock your private key: ")
        private_key = load_private_key(user_id, password)
        if not private_key:
            print("Incorrect password or key file issue.")

    filename_to_download = input("Enter the name of the encrypted file to download (e.g., user_file.encrypted): ")
    encrypted_file_path = os.path.join(SERVER_STORAGE_DIR, filename_to_download)
    metadata_file_path = encrypted_file_path.replace(".encrypted", ".metadata")

    if not os.path.exists(encrypted_file_path) or not os.path.exists(metadata_file_path):
        print("Error: Encrypted file or metadata not found on the server.")
        return

    try:
        with open(encrypted_file_path, "rb") as f:
            ciphertext = f.read()
        with open(metadata_file_path, "r") as f:
            iv_hex, encrypted_key_hex = f.read().split(":")
            iv = bytes.fromhex(iv_hex)
            encrypted_key = bytes.fromhex(encrypted_key_hex)

        # Decrypt the symmetric key using the server's private key (in this simplified model)
        symmetric_key = decrypt_file(iv, encrypted_key, ciphertext, server_private_key)
        if symmetric_key:
            # Now decrypt the actual file content using the decrypted symmetric key
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            original_filename = filename_to_download.replace(f"{filename_to_download.split('_')[0]}_", "").replace(".encrypted", "")
            download_path = f"downloaded_{original_filename}"
            with open(download_path, "wb") as f:
                f.write(plaintext)
            print(f"File downloaded and decrypted to '{download_path}'.")
        else:
            print("Error: Symmetric key decryption failed (likely not intended for this server).")

    except Exception as e:
        print(f"Download error: {e}")

def login():
    user_id = input("Enter your username: ")
    if os.path.exists(get_user_keys_path(user_id, "private_key.enc")):
        return user_id
    else:
        print("Invalid user.")
        return None

if __name__ == "__main__":
    print("Secure Cloud File Storage (Simulation with Improved Security)")

    # Load server's public and private keys
    SERVER_PUBLIC_KEY_FILE = "server_public_key.pem"
    SERVER_PRIVATE_KEY_FILE = "server_private_key.pem"
    try:
        with open(SERVER_PUBLIC_KEY_FILE, "rb") as f:
            server_public_key_pem = f.read()
        with open(SERVER_PRIVATE_KEY_FILE, "rb") as f:
            server_private_key_pem = f.read()
        from crypto_utils import deserialize_public_key, deserialize_private_key
        server_public_key = deserialize_public_key(server_public_key_pem)
        server_private_key = deserialize_private_key(server_private_key_pem)
    except FileNotFoundError:
        print("Error: Server key files not found. Please run server_simulation.py first.")
        exit()

    current_user = None

    while True:
        print("\nOptions:")
        if current_user:
            print(f"Logged in as: {current_user}")
            print("3. Upload File")
            print("4. Download File")
            print("5. Logout")
        else:
            print("1. Register User")
            print("2. Login")
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == '1' and not current_user:
            register_user()
        elif choice == '2' and not current_user:
            logged_in_user = login()
            if logged_in_user:
                current_user = logged_in_user
        elif choice == '3' and current_user:
            upload_file(current_user, server_public_key)
        elif choice == '4' and current_user:
            download_file(current_user, server_private_key)
        elif choice == '5' and current_user:
            print(f"Logged out: {current_user}")
            current_user = None
        elif choice == '6':
            print("Exiting.")
            break
        else:
            print("Invalid choice or action not allowed in the current state.")