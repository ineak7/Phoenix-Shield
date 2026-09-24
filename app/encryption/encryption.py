import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
KEY_SIZE = 32


def generate_key():
    """
    Generate a 256-bit AES encryption key.
    """
    return AESGCM.generate_key(bit_length=256)


def encrypt_file_data(data: bytes, key: bytes) -> bytes:
    """
    Encrypt file data using AES-256-GCM.

    Output format:

        [12-byte nonce][ciphertext + authentication tag]
    """

    if len(key) != KEY_SIZE:
        raise ValueError("Encryption key must be 256 bits.")

    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    encrypted_data = aesgcm.encrypt(
        nonce,
        data,
        None
    )

    return nonce + encrypted_data


def decrypt_file_data(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt data produced by encrypt_file_data().
    """

    if len(key) != KEY_SIZE:
        raise ValueError("Encryption key must be 256 bits.")

    if len(encrypted_data) < NONCE_SIZE:
        raise ValueError("Invalid encrypted data.")

    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]

    aesgcm = AESGCM(key)

    decrypted_data = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    return decrypted_data