import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from ..utils.config import AES_KEY_SIZE, AES_MODE
from .hash import generate_hash_from_pin


def encrypt_aes(data: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Encrypts data using the AES algorithm.

    @param data Data to encrypt.
    @param key AES key.
    @param iv Initialization vector (default: random).
    @return Tuple (encrypted data, initialization vector).
    """
    if iv is None:
        iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    if AES_MODE == "CBC":
        mode = modes.CBC(iv)
    elif AES_MODE == "GCM":
        mode = modes.GCM(iv)
    else:
        raise ValueError(f"Unsupported AES mode: {AES_MODE}")

    cipher = Cipher(algorithms.AES(key), mode)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data, iv


def decrypt_aes(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypts data encrypted with the AES algorithm.

    @param encrypted_data Encrypted data.
    @param key AES key.
    @param iv Initialization vector.
    @return Decrypted data.
    """
    if AES_MODE == "CBC":
        mode = modes.CBC(iv)
    elif AES_MODE == "GCM":
        mode = modes.GCM(iv)
    else:
        raise ValueError(f"Unsupported AES mode: {AES_MODE}")

    cipher = Cipher(algorithms.AES(key), mode)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data


def encrypt_private_key(private_key: bytes, pin: str) -> Tuple[bytes, bytes]:
    """
    Encrypts an RSA private key using the AES algorithm.

    @param private_key RSA private key.
    @param pin User's PIN.
    @return Tuple (encrypted private key, initialization vector).
    """
    salt = os.urandom(16)
    key = generate_hash_from_pin(pin, salt)
    encrypted_key, iv = encrypt_aes(private_key, key)
    result = salt + iv + encrypted_key
    return result, iv


def decrypt_private_key(encrypted_key: bytes, pin: str) -> bytes:
    """
    Decrypts an RSA private key encrypted with the AES algorithm.

    @param encrypted_key Encrypted RSA private key.
    @param pin User's PIN.
    @return Decrypted RSA private key.
    """
    salt = encrypted_key[:16]
    iv = encrypted_key[16:32]
    encrypted_data = encrypted_key[32:]
    key = generate_hash_from_pin(pin, salt)
    private_key = decrypt_aes(encrypted_data, key, iv)
    return private_key
