import socket
from utils import generate_dh_keypair, generate_shared_secret
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

def connect_to_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 5000))  # Connect to server

    # Perform Diffie-Hellman key exchange with server
    private_key, public_key, parameters = generate_dh_keypair()

    # Send public key to server
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"Client public key (PEM):\n{public_key_pem.decode()}")
    client.send(public_key_pem)

    # Receive the server's public key
    server_public_key_bytes = client.recv(1024)
    print(f"Server public key (PEM) received:\n{server_public_key_bytes.decode()}")
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    # Generate shared secret
    try:
        shared_secret = generate_shared_secret(private_key, server_public_key)
        print(f"Shared secret generated: {shared_secret.hex()}")
    except ValueError as e:
        print(f"Error computing shared secret: {e}")
        client.close()
        return

    client.close()

if __name__ == "__main__":
    connect_to_server()
