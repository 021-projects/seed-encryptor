import hashlib
import argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass
import os


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key using PBKDF2 (consistent for decryption)."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)


def decrypt_seed(encrypted_data: bytes, password: str) -> str:
    """Decrypt a seed phrase encrypted with AES-256-GCM."""
    salt, nonce, ciphertext = encrypted_data[:16], encrypted_data[16:28], encrypted_data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def read_password_from_file(path: str) -> str:
    """Read and return the first line from a password file."""
    with open(path, 'r', encoding='utf-8') as file:
        return file.readline().strip()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt an AES-256-GCM encrypted seed phrase.")
    parser.add_argument("--password-file", help="Path to file containing the password")
    args = parser.parse_args()

    # Ask for encrypted seed (hex)
    encrypted_hex = getpass("Enter the encrypted seed phrase (hex): ")

    # Get password either from file or prompt
    if args.password_file:
        if not os.path.isfile(args.password_file):
            print(f"❌ Error: Password file '{args.password_file}' not found.")
            exit(1)
        password = read_password_from_file(args.password_file)
    else:
        password = getpass("Enter your password securely: ")

    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted_seed = decrypt_seed(encrypted_bytes, password)
        print(f"✅ Decrypted Seed: {decrypted_seed}")
    except Exception as e:
        print(f"❌ Decryption failed: {str(e)}")
