import socket
import threading
from encryption import generate_key, get_cipher, decrypt_message
from security import verify_hash

HOST = "127.0.0.1"
PORT = 5000

VALID_USERS = {
    "admin": "1234",
    "user": "pass"
}

def log_message(msg):
    with open("log.txt", "a") as f:
        f.write(msg + "\n")

def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")

    try:
        # STEP 1: Key exchange
        key = generate_key()
        conn.send(key)
        cipher = get_cipher(key)

        # STEP 2: Authentication
        auth_data = conn.recv(1024)
        decrypted_auth = decrypt_message(cipher, auth_data)

        username, password = decrypted_auth.split(":")

        if username in VALID_USERS and VALID_USERS[username] == password:
            conn.send(cipher.encrypt(b"AUTH_SUCCESS"))
            print(f"[AUTH SUCCESS] {username} from {addr}")
        else:
            conn.send(cipher.encrypt(b"AUTH_FAILED"))
            print(f"[AUTH FAILED] {addr}")
            conn.close()
            return

        # STEP 3: Message handling
        while True:
            data = conn.recv(1024)
            if not data:
                break

            print(f"\n[INTERCEPTED ENCRYPTED]: {data}")

            decrypted_data = decrypt_message(cipher, data)

            # Split message and hash
            try:
                message, received_hash = decrypted_data.split("||")
            except:
                print("[ERROR] Invalid message format")
                continue

            # Verify integrity
            if verify_hash(message, received_hash):
                print(f"[VALID] {username}: {message}")
                log_message(f"{addr} ({username}): {message}")
            else:
                print(f"[WARNING] Data tampered from {username}!")

    except Exception as e:
        print(f"[ERROR]: {e}")

    finally:
        conn.close()
        print(f"[-] Disconnected: {addr}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print("VPN Server running...")
    print("Waiting for connections...\n")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()