from typing import Tuple, Optional
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

from ..utils.config import RSA_KEY_SIZE, HASH_ALGORITHM


def generate_rsa_key_pair() -> Tuple[bytes, bytes]:
    """
    Generates an RSA key pair.

    @return Tuple (private key, public key) in PEM format.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def sign_data(data: bytes, private_key_pem: bytes, password: Optional[bytes] = None) -> bytes:
    """
    Signs data using an RSA private key.

    @param data Data to sign.
    @param private_key_pem RSA private key in PEM format.
    @param password Password for the private key (if encrypted).
    @return Signature as bytes.
    """
    private_key = load_pem_private_key(private_key_pem, password=password)

    if HASH_ALGORITHM == "sha256":
        hash_algorithm = hashes.SHA256()
    elif HASH_ALGORITHM == "sha384":
        hash_algorithm = hashes.SHA384()
    elif HASH_ALGORITHM == "sha512":
        hash_algorithm = hashes.SHA512()
    else:
        raise ValueError(f"Unsupported hash algorithm: {HASH_ALGORITHM}")

    signature = private_key.sign(
        data,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hash_algorithm),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hash_algorithm
    )

    return signature


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verifies a signature using an RSA public key.

    @param data The data that was signed.
    @param signature The signature to verify.
    @param public_key_pem RSA public key in PEM format.
    @return True if the signature is valid, False otherwise.
    """
    public_key = load_pem_public_key(public_key_pem)

    if HASH_ALGORITHM == "sha256":
        hash_algorithm = hashes.SHA256()
    elif HASH_ALGORITHM == "sha384":
        hash_algorithm = hashes.SHA384()
    elif HASH_ALGORITHM == "sha512":
        hash_algorithm = hashes.SHA512()
    else:
        raise ValueError(f"Unsupported hash algorithm: {HASH_ALGORITHM}")

    try:
        public_key.verify(
            signature,
            data,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hash_algorithm),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hash_algorithm
        )
        return True
    except InvalidSignature:
        return False
