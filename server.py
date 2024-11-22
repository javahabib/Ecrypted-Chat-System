import socket
from utils import generate_dh_keypair, generate_shared_secret
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 5000))
    server.listen(1)
    print("Server listening on port 5000...")
    conn, addr = server.accept()
    print(f"Connection from {addr}")

    # Generate Diffie-Hellman keypair
    private_key, public_key, parameters = generate_dh_keypair()

    # Send public key to client
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"Server public key (PEM):\n{public_key_pem.decode()}")
    conn.send(public_key_pem)

    # Receive the client's public key
    client_public_key_bytes = conn.recv(1024)
    print(f"Client public key (PEM) received:\n{client_public_key_bytes.decode()}")
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)

    # Generate shared secret
    try:
        shared_secret = generate_shared_secret(private_key, client_public_key)
        print(f"Shared secret generated: {shared_secret.hex()}")
    except ValueError as e:
        print(f"Error computing shared secret: {e}")
        conn.close()
        return

    conn.close()

if __name__ == "__main__":
    start_server()
