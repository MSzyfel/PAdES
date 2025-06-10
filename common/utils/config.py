"""
Module containing the application configuration.

This module defines constants and settings used throughout the project.
"""

import os
import platform

VERSION = "1.0.0"

APP_NAME = "PAdES Signature Tool"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESOURCES_DIR = os.path.join(BASE_DIR, "resources")
TEMP_DIR = os.path.join(BASE_DIR, "temp")

# Cryptographic settings
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 256
HASH_ALGORITHM = "sha256"
AES_MODE = "CBC"

PRIVATE_KEY_FILENAME = "private_key.enc"
PUBLIC_KEY_FILENAME = "public_key.pem"
SIGNATURE_FILENAME = "signature.bin"

PDF_EXTENSION = ".pdf"
SIGNED_PDF_SUFFIX = "_signed"

if platform.system() == "Windows":  # Windows
    USB_DRIVE_LETTER = "EFGH"
elif platform.system() == "Darwin":  # macOS
    USB_MOUNT_PATH = "/Volumes"
else:  # Linux
    USB_MOUNT_PATH = "/media"

WINDOW_WIDTH = 400
WINDOW_HEIGHT = 500
WINDOW_TITLE = APP_NAME
ICON_SIZE = 32

MSG_KEY_GENERATION_SUCCESS = "RSA keys were generated successfully."
MSG_KEY_GENERATION_FAILURE = "Error occurred while generating RSA keys."
MSG_PRIVATE_KEY_SAVED = "Private key has been saved to the USB drive."
MSG_PUBLIC_KEY_SAVED = "Public key has been saved on disk."
MSG_USB_DETECTED = "USB drive with private key detected."
MSG_USB_NOT_DETECTED = "USB drive with private key not detected."
MSG_PRIVATE_KEY_LOADED = "Private key has been loaded."
MSG_PRIVATE_KEY_DECRYPTED = "Private key has been decrypted."
MSG_DOCUMENT_SIGNED = "Document has been signed."
MSG_SIGNATURE_VERIFIED = "Signature has been successfully verified."
MSG_SIGNATURE_INVALID = "Signature is invalid."
MSG_DOCUMENT_MODIFIED = "Document was modified after signing."
