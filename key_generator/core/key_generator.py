"""
RSA key generator module.

This module implements an RSA key generator used by the helper application.
"""

from typing import Tuple

from common.crypto.rsa import generate_rsa_key_pair
from common.crypto.aes import encrypt_private_key
from common.usb.storage import save_private_key, save_public_key


class KeyGenerator:
    """
    RSA key generator class.
    """

    def __init__(self):
        """
        Initializes the key generator.
        """
        self.private_key = None
        self.public_key = None
        self.encrypted_private_key = None

    def generate_keys(self) -> Tuple[bytes, bytes]:
        """
        Generates an RSA key pair.

        @return: A tuple (private_key, public_key) in PEM format.
        """
        self.private_key, self.public_key = generate_rsa_key_pair()
        return self.private_key, self.public_key

    def encrypt_private_key(self, pin: str) -> bytes:
        """
        Encrypts the private RSA key using AES.

        @param pin: User PIN.
        @return: Encrypted private key bytes.
        """
        if self.private_key is None:
            raise ValueError("Private key has not been generated.")

        self.encrypted_private_key, _ = encrypt_private_key(self.private_key, pin)
        return self.encrypted_private_key

    def save_keys(self, drive_path: str, public_key_path: str) -> Tuple[bool, bool]:
        """
        Saves the private and public keys to disk.

        @param drive_path: Path to the USB drive.
        @param public_key_path: Path to the public key file.
        @return: A tuple (was_private_saved, was_public_saved).
        """
        if self.encrypted_private_key is None:
            raise ValueError("Private key has not been encrypted.")
        if self.public_key is None:
            raise ValueError("Public key has not been generated.")

        private_ok = save_private_key(drive_path, self.encrypted_private_key)
        public_ok = save_public_key(public_key_path, self.public_key)

        return private_ok, public_ok
