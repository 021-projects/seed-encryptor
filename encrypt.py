import os
import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key using PBKDF2 (suitable for AES-GCM)."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)


def encrypt_seed(seed_phrase: str, password: str) -> bytes:
    """Encrypt a seed phrase using AES-256-GCM with PBKDF2 key derivation."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, seed_phrase.encode(), None)
    return salt + nonce + ciphertext  # salt (16) + nonce (12) + ciphertext


def read_password_from_file(path: str) -> str:
    """Read and return the first line from a password file."""
    with open(path, 'r', encoding='utf-8') as file:
        return file.readline().strip()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt a seed phrase securely.")
    parser.add_argument("--password-file", help="Path to file containing the password")
    args = parser.parse_args()

    # Prompt for seed phrase
    seed_phrase = getpass("Enter your seed phrase securely: ")

    if args.password_file:
        if not os.path.isfile(args.password_file):
            print(f"❌ Error: Password file '{args.password_file}' not found.")
            exit(1)
        password = read_password_from_file(args.password_file)
    else:
        # Prompt for password securely with confirmation
        while True:
            password = getpass("Enter your encryption password securely: ")
            confirm_password = getpass("Confirm your password: ")
            if password == confirm_password:
                break
            print("Passwords do not match. Please try again.")

    encrypted_data = encrypt_seed(seed_phrase, password)
    print(f"🔐 Encrypted Seed (hex): {encrypted_data.hex()}")
