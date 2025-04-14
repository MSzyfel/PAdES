from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import getpass
import hashlib


def generate_keys(PIN, key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Na tym etapie nie szyfrujemy
    )
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    aes_key = hashlib.sha256(PIN).digest()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding: uzupełniamy dane do wielokrotności 16 bajtów (AES block size)
    pad_len = 16 - (len(private_key_bytes) % 16)
    padded_private_key = private_key_bytes + bytes([pad_len]) * pad_len

    encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()
    return public_key_bytes, encrypted_private_key
