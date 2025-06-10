"""
Signature model module.

This module defines the data model for digital signatures used in the application.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Signature:
    """
    Represents a digital signature.

    Attributes:
        signature_data (bytes): The actual digital signature in bytes.
        signer_name (str): Name of the signer.
        timestamp (datetime): Time when the document was signed.
        document_hash (bytes): Hash of the signed document.
    """
    signature_data: bytes
    signer_name: str
    timestamp: datetime
    document_hash: bytes

    def to_dict(self) -> dict:
        """
        Converts the signature object into a dictionary.

        Returns:
            dict: Dictionary representation of the signature.
        """
        return {
            "signature_data": self.signature_data,
            "signer_name": self.signer_name,
            "timestamp": self.timestamp.isoformat(),
            "document_hash": self.document_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Signature':
        """
        Creates a Signature instance from a dictionary.

        Args:
            data (dict): Dictionary containing signature information.

        Returns:
            Signature: The constructed Signature object.
        """
        return cls(
            signature_data=data["signature_data"],
            signer_name=data["signer_name"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            document_hash=data["document_hash"],
        )
