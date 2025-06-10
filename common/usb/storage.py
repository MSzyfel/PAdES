"""
Module with functions for file operations on USB drives.

This module handles reading and writing private/public keys on USB devices.
"""

import os
from typing import Optional

from ..utils.config import PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME


def save_private_key(drive_path: str, key_data: bytes) -> bool:
    """
    Saves the encrypted private key to the USB drive.

    @param drive_path: Path to the USB drive.
    @param key_data: Encrypted private key data.
    @return: True if saved successfully, otherwise False.
    """
    try:
        path = os.path.join(drive_path, PRIVATE_KEY_FILENAME)
        with open(path, 'wb') as f:
            f.write(key_data)
        return True
    except Exception as e:
        print(f"Error saving private key: {e}")
        return False


def load_private_key(drive_path: str) -> Optional[bytes]:
    """
    Loads the encrypted private key from the USB drive.

    @param drive_path: Path to the USB drive.
    @return: The key data or None if loading failed.
    """
    try:
        path = os.path.join(drive_path, PRIVATE_KEY_FILENAME)
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None


def save_public_key(file_path: str, key_data: bytes) -> bool:
    """
    Saves the public key to the given file path.

    @param file_path: Path to the file.
    @param key_data: Public key data.
    @return: True if saved successfully, otherwise False.
    """
    try:
        with open(file_path, 'wb') as f:
            f.write(key_data)
        return True
    except Exception as e:
        print(f"Error saving public key: {e}")
        return False


def load_public_key(file_path: str) -> Optional[bytes]:
    """
    Loads the public key from the given file path.

    @param file_path: Path to the file.
    @return: The key data or None if loading failed.
    """
    try:
        if not os.path.exists(file_path):
            return None
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None


def get_default_public_key_path() -> str:
    """
    Returns the default path for the public key file.

    @return: Default public key file path in the user's home directory.
    """
    return os.path.join(os.path.expanduser("~"), PUBLIC_KEY_FILENAME)
