import socket
from encryption import get_cipher, encrypt_message, decrypt_message
from security import generate_hash

HOST = "127.0.0.1"
PORT = 5000

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    print("Connected to VPN Server")

    # STEP 1: Receive key
    key = client.recv(1024)
    cipher = get_cipher(key)

    # STEP 2: Authentication
    username = input("Enter username: ")
    password = input("Enter password: ")

    auth_message = f"{username}:{password}"
    client.send(encrypt_message(cipher, auth_message))

    response = decrypt_message(cipher, client.recv(1024))

    if response != "AUTH_SUCCESS":
        print("Authentication Failed!")
        client.close()
        return

    print("Authentication Successful!\n")

    # STEP 3: Send messages with hash
    while True:
        message = input("Enter message: ")

        if message.lower() == "exit":
            break

        hash_value = generate_hash(message)
        combined = message + "||" + hash_value
        # Simulate tampering by using a fake hash
        # fake_hash = "0"*64  
        # combined = message + "||" + fake_hash

        encrypted = encrypt_message(cipher, combined)

        print("[ENCRYPTED]:", encrypted)

        client.send(encrypted)

    client.close()

if __name__ == "__main__":
    start_client()