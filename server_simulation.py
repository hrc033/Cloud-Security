import os
from crypto_utils import generate_rsa_key_pair, serialize_public_key, serialize_private_key

SERVER_STORAGE_DIR = "server_files"

if not os.path.exists(SERVER_STORAGE_DIR):
    os.makedirs(SERVER_STORAGE_DIR)

# In a real server, you would have more sophisticated logic
# This simulation just creates a directory to store files.

# For the purpose of the client, we need the server's public key
# In a real system, this would be managed securely by the server.
from crypto_utils import generate_rsa_key_pair, serialize_public_key

SERVER_PUBLIC_KEY_FILE = "server_public_key.pem"
SERVER_PRIVATE_KEY_FILE = "server_private_key.pem"

if not os.path.exists(SERVER_PRIVATE_KEY_FILE):
    server_private_key, server_public_key = generate_rsa_key_pair()
    with open(SERVER_PRIVATE_KEY_FILE, "wb") as f:
        f.write(serialize_private_key(server_private_key))
    with open(SERVER_PUBLIC_KEY_FILE, "wb") as f:
        f.write(serialize_public_key(server_public_key))
    print("Server key pair generated.")
else:
    print("Server key pair already exists.")

print(f"Simulated server storage directory: {SERVER_STORAGE_DIR}")
print("Run the client.py file to interact with the storage.")