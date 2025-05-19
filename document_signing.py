import os
import string
import ctypes
import sys
import getpass
import hashlib

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode

import hashlib
import json
from pathlib import Path
from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def is_removable_drive(drive_letter):
    drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{drive_letter}:\\")
    return drive_type == 2


def find_pendrive_with_key(filename="private_key.pem"):
    removable_drives = [f"{letter}:\\" for letter in string.ascii_uppercase if
                        os.path.exists(f"{letter}:\\") and is_removable_drive(letter)]
    for drive in removable_drives:
        for root, dirs, files in os.walk(drive):
            if filename in files:
                full_path = os.path.join(root, filename)
                return full_path
    sys.exit(1)


def decrypt_private_key(encrypted_key_path):
    with open(encrypted_key_path, "rb") as f:
        data = f.read()
    iv = data[:16]
    encrypted_data = data[16:]
    pin = getpass.getpass("Podaj PIN ").encode()
    aes_key = hashlib.sha256(pin).digest()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_private_key = decryptor.update(encrypted_data) + decryptor.finalize()
    pad_len = padded_private_key[-1]
    private_key_bytes = padded_private_key[:-pad_len]
    return serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )


def sign_pdf(input_path: str, output_path: str, private_key: RSAPrivateKey):
    # 1. Wczytaj dane PDF
    with open(input_path, 'rb') as f:
        pdf_data = f.read()

    # 2. Oblicz hash SHA-256 zawartości PDF
    digest = hashlib.sha256(pdf_data).digest()

    # 3. Podpisz hash kluczem RSA
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # 4. Wczytaj PDF i dodaj podpis do metadanych
    reader = PdfReader(input_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    metadata = reader.metadata or {}
    metadata.update({
        "/Signature": json.dumps({
            "algorithm": "SHA256withRSA",
            "signature": signature.hex()
        })
    })
    writer.add_metadata(metadata)

    # 5. Zapisz podpisany PDF
    with open(output_path, 'wb') as f:
        writer.write(f)

    print(f"✅ PDF został podpisany i zapisany do: {output_path}")


if __name__ == "__main__":
    print("test")
    encrypted_key_file = find_pendrive_with_key()
    private_key = decrypt_private_key(encrypted_key_file)

    pdf_to_sign = input("Podaj ścieżkę do dokumentu PDF: ").strip()
    output_pdf = "signed_document.pdf"

    sign_pdf(pdf_to_sign, output_pdf, private_key)
