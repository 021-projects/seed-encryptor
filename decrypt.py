import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key using PBKDF2 (consistent for decryption)."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)


def decrypt_seed(encrypted_data: bytes, password: str) -> str:
    """Decrypt a seed phrase encrypted with AES-256-GCM."""
    salt, nonce, ciphertext = encrypted_data[:16], encrypted_data[16:28], encrypted_data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


if __name__ == "__main__":
    # We will no longer ask for the encrypted_hex or password via command-line arguments
    # Instead, we will ask securely for both using getpass
    encrypted_hex = getpass("Please enter the encrypted seed phrase (hex): ")
    password = getpass("Please enter your password for decryption securely: ")

    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted_seed = decrypt_seed(encrypted_bytes, password)
    print(f"Decrypted Seed: {decrypted_seed}")
