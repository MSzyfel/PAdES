import hashlib
import os
from typing import Union, Optional

from ..utils.config import HASH_ALGORITHM


def generate_hash(data: Union[str, bytes], algorithm: Optional[str] = None) -> bytes:
    """
    Generates a hash from the given data.

    @param data Input data to hash.
    @param algorithm Hash algorithm to use (default: from config).
    @return Hash as bytes.
    """
    if algorithm is None:
        algorithm = HASH_ALGORITHM

    if isinstance(data, str):
        data = data.encode('utf-8')

    hash_obj = hashlib.new(algorithm)
    hash_obj.update(data)
    return hash_obj.digest()


def generate_hash_from_pin(pin: str, salt: Optional[bytes] = None) -> bytes:
    """
    Generates a hash from a user's PIN to be used as an AES key.

    @param pin User PIN.
    @param salt Salt to strengthen the hash (default: random).
    @return Derived key as bytes.
    """
    if salt is None:
        salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        pin.encode('utf-8'),
        salt,
        iterations=100000,
        dklen=32
    )

    return key


def verify_hash(data: Union[str, bytes], hash_value: bytes, algorithm: Optional[str] = None) -> bool:
    """
    Verifies whether the hash of the given data matches the expected hash.

    @param data Input data.
    @param hash_value Expected hash.
    @param algorithm Hash algorithm to use (default: from config).
    @return True if the hash matches, False otherwise.
    """
    generated_hash = generate_hash(data, algorithm)
    return generated_hash == hash_value
