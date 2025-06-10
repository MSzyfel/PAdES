"""
Unit tests for cryptographic modules.

This module contains unit tests for cryptographic modules.
"""

import unittest
import os

from common.crypto.hash import generate_hash, generate_hash_from_pin, verify_hash
from common.crypto.aes import encrypt_aes, decrypt_aes, encrypt_private_key, decrypt_private_key
from common.crypto.rsa import generate_rsa_key_pair, sign_data, verify_signature


class TestHash(unittest.TestCase):
    """
    Unit tests for the hash functions module.
    """

    def test_generate_hash(self):
        """
        Tests the hash generation function.
        """
        data = "test"
        hash_value = generate_hash(data)
        self.assertIsNotNone(hash_value)
        self.assertIsInstance(hash_value, bytes)

    def test_generate_hash_from_pin(self):
        """
        Tests the function generating a hash from a PIN.
        """
        pin = "1234"
        salt = os.urandom(16)
        key = generate_hash_from_pin(pin, salt)
        self.assertIsNotNone(key)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)  # 256 bits

    def test_verify_hash(self):
        """
        Tests the hash verification function.
        """
        data = "test"
        hash_value = generate_hash(data)
        self.assertTrue(verify_hash(data, hash_value))
        self.assertFalse(verify_hash("test2", hash_value))


class TestAES(unittest.TestCase):
    """
    Unit tests for the AES encryption module.
    """

    def test_encrypt_decrypt_aes(self):
        """
        Tests AES encryption and decryption functions.
        """
        data = b"test"
        key = os.urandom(32)  # 256 bits
        encrypted_data, iv = encrypt_aes(data, key)
        self.assertIsNotNone(encrypted_data)
        self.assertIsNotNone(iv)
        self.assertIsInstance(encrypted_data, bytes)
        self.assertIsInstance(iv, bytes)
        self.assertNotEqual(data, encrypted_data)

        decrypted_data = decrypt_aes(encrypted_data, key, iv)
        self.assertEqual(data, decrypted_data)

    def test_encrypt_decrypt_private_key(self):
        """
        Tests the private key encryption and decryption functions.
        """
        private_key = b"test_private_key"
        pin = "1234"
        encrypted_key, _ = encrypt_private_key(private_key, pin)
        self.assertIsNotNone(encrypted_key)
        self.assertIsInstance(encrypted_key, bytes)
        self.assertNotEqual(private_key, encrypted_key)

        decrypted_key = decrypt_private_key(encrypted_key, pin)
        self.assertEqual(private_key, decrypted_key)


class TestRSA(unittest.TestCase):
    """
    Unit tests for the RSA operations module.
    """

    def test_generate_rsa_key_pair(self):
        """
        Tests the RSA key pair generation function.
        """
        private_key, public_key = generate_rsa_key_pair()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertIsInstance(private_key, bytes)
        self.assertIsInstance(public_key, bytes)
        self.assertIn(b"BEGIN PRIVATE KEY", private_key)
        self.assertIn(b"BEGIN PUBLIC KEY", public_key)

    def test_sign_verify_data(self):
        """
        Tests the signing and signature verification functions.
        """
        private_key, public_key = generate_rsa_key_pair()
        data = b"test"
        signature = sign_data(data, private_key)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)

        self.assertTrue(verify_signature(data, signature, public_key))
        self.assertFalse(verify_signature(b"test2", signature, public_key))


if __name__ == "__main__":
    unittest.main()

