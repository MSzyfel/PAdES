from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def load_public_key(path: str):
    with open(path, "rb") as f:
        key_data = f.read()
        return serialization.load_pem_public_key(key_data)


def verify_signature(public_key_path: str, data: bytes, signature: bytes) -> bool:
    """
    Verifies the RSA signature of data using the given public key.

    :param public_key_path: Path to the PEM-encoded RSA public key.
    :param data: The original data that was signed.
    :param signature: The signature to verify.
    :return: True if signature is valid, False otherwise.
    """
    public_key = load_public_key(public_key_path)

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        raise RuntimeError(f"Verification failed due to unexpected error: {e}")
