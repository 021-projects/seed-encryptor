import os
import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key using PBKDF2 (more suitable for AES-GCM)."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)


def encrypt_seed(seed_phrase: str, password: str) -> bytes:
    """Encrypt a seed phrase using AES-256-GCM with PBKDF2 key derivation."""
    salt = os.urandom(16)  # Random salt
    key = derive_key(password, salt)
    nonce = os.urandom(12)  # AES-GCM nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, seed_phrase.encode(), None)
    return salt + nonce + ciphertext  # Store salt + nonce + encrypted data


if __name__ == "__main__":
    # No command-line arguments for seed or password
    parser = argparse.ArgumentParser(description="Encrypt a seed phrase securely.")
    args = parser.parse_args()

    # Prompting securely for seed phrase and password
    seed_phrase = getpass("Please enter your seed phrase securely: ")
    password = getpass("Please enter your password for encryption securely: ")

    encrypted_data = encrypt_seed(seed_phrase, password)
    print(f"Encrypted Seed (hex): {encrypted_data.hex()}")
