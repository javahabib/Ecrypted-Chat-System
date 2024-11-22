import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Generate Diffie-Hellman parameters and keypair
def generate_dh_keypair():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, parameters

# Generate shared secret using Diffie-Hellman
def generate_shared_secret(private_key, peer_public_key):
    try:
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret
    except Exception as e:
        raise ValueError(f"Error computing shared secret: {e}")

# Derive a 16-byte AES key from the shared secret
def derive_aes_key(shared_secret):
    # Hash the shared secret and truncate to 16 bytes for AES-128
    return hashlib.sha256(shared_secret).digest()[:16]

# AES encryption (AES-128-CBC)
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_length = 16 - len(plaintext) % 16
    padded_plaintext = plaintext + bytes([padding_length]) * padding_length
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext

# AES decryption (AES-128-CBC)
def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_plaintext[-1]
    return padded_plaintext[:-padding_length]

# Hash password using SHA-256 with salt
def hash_password(password, salt):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(salt)
    digest.update(password.encode())
    return digest.finalize()

# Generate salt
def generate_salt():
    return os.urandom(32)  # 256-bit salt
