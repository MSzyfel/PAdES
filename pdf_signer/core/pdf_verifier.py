"""
Module for verifying PDF document signatures.

This module implements PDF signature verification functions used by the main application.
"""

import io
import hashlib
import base64
from typing import Tuple, Optional, Dict, Any

from PyPDF2 import PdfReader
from PyPDF2.generic import DictionaryObject, ByteStringObject, IndirectObject, TextStringObject

from common.crypto.rsa import verify_signature
from common.utils.config import HASH_ALGORITHM


class PDFVerifier:
    """
    Class for verifying PDF document signatures.
    """

    def __init__(self, public_key: bytes):
        """
        Initializes PDF signature verifier.

        @param public_key RSA public key in PEM format.
        """
        self.public_key = public_key

    def verify_pdf(self, pdf_path: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Verifies the signature of a PDF document.

        @param pdf_path Path to the PDF document.
        @return Tuple (is signature valid, message, signature info dict).
        """
        try:
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()

            signature_info = self._extract_signature_from_pdf(pdf_data)
            if signature_info is None:
                return False, "Document does not contain a signature.", None

            signature_data = signature_info["signature"]
            document_hash = signature_info.get("document_hash")
            signer_name = signature_info.get("name", "Unknown")
            timestamp = signature_info.get("timestamp", "Unknown")
            digest_method = signature_info.get("digest_method", HASH_ALGORITHM.upper())

            if document_hash is None:
                hash_obj = hashlib.new(HASH_ALGORITHM)
                hash_obj.update(pdf_data)
                document_hash = hash_obj.digest()
                print("Warning: Using hash of entire document which may lead to incorrect verification.")

            is_valid = verify_signature(document_hash, signature_data, self.public_key)

            message = "Signature is valid." if is_valid else "Signature is invalid."

            signature_info = {
                "signer_name": signer_name,
                "timestamp": timestamp,
                "digest_method": digest_method
            }

            return is_valid, message, signature_info
        except Exception as e:
            print(f"Error during PDF signature verification: {e}")
            return False, f"Error occurred during signature verification: {e}", None

    def _extract_signature_from_pdf(self, pdf_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Extracts the signature from a PDF document.

        @param pdf_data PDF document data.
        @return Dictionary with signature info or None if no signature found.
        """
        try:
            reader = PdfReader(io.BytesIO(pdf_data))

            if "/AcroForm" not in reader.trailer["/Root"]:
                print("Document does not contain AcroForm.")
                return None

            acroform = reader.trailer["/Root"]["/AcroForm"]

            if "/Fields" not in acroform:
                print("AcroForm does not contain Fields.")
                return None

            fields = acroform["/Fields"]

            for field in fields:
                if isinstance(field, IndirectObject):
                    field = field.get_object()

                if isinstance(field, DictionaryObject):
                    if "/Type" in field and field["/Type"] == "/Sig":
                        signature_info = {}

                        if "/Contents" in field:
                            contents = field["/Contents"]
                            if isinstance(contents, ByteStringObject):
                                signature_info["signature"] = bytes(contents)
                            elif isinstance(contents, str):
                                try:
                                    signature_info["signature"] = bytes.fromhex(contents)
                                except ValueError:
                                    try:
                                        signature_info["signature"] = base64.b64decode(contents)
                                    except Exception:
                                        signature_info["signature"] = contents.encode('latin1')
                            else:
                                signature_info["signature"] = str(contents).encode('latin1')

                        document_hash_encoding = field.get("/DocumentHashEncoding")

                        if "/DocumentHash" in field:
                            document_hash = field["/DocumentHash"]

                            if isinstance(document_hash, ByteStringObject):
                                document_hash_bytes = bytes(document_hash)
                                if document_hash_encoding == "/BASE64":
                                    try:
                                        document_hash_bytes = base64.b64decode(document_hash_bytes)
                                    except Exception:
                                        print("Failed to decode document hash from base64.")
                                signature_info["document_hash"] = document_hash_bytes

                            elif isinstance(document_hash, TextStringObject):
                                document_hash_str = str(document_hash)
                                if document_hash_encoding == "/BASE64":
                                    try:
                                        signature_info["document_hash"] = base64.b64decode(document_hash_str)
                                    except Exception:
                                        print("Failed to decode document hash from base64. Generating new hash.")
                                        hash_obj = hashlib.new(HASH_ALGORITHM)
                                        hash_obj.update(pdf_data)
                                        signature_info["document_hash"] = hash_obj.digest()
                                else:
                                    try:
                                        signature_info["document_hash"] = bytes.fromhex(document_hash_str)
                                    except ValueError:
                                        try:
                                            signature_info["document_hash"] = base64.b64decode(document_hash_str)
                                        except Exception:
                                            signature_info["document_hash"] = document_hash_str.encode('utf-8', errors='ignore')

                            elif isinstance(document_hash, str):
                                if document_hash_encoding == "/BASE64":
                                    try:
                                        signature_info["document_hash"] = base64.b64decode(document_hash)
                                    except Exception:
                                        print("Failed to decode document hash from base64.")
                                        signature_info["document_hash"] = document_hash.encode('utf-8', errors='ignore')
                                else:
                                    try:
                                        signature_info["document_hash"] = bytes.fromhex(document_hash)
                                    except ValueError:
                                        try:
                                            signature_info["document_hash"] = base64.b64decode(document_hash)
                                        except Exception:
                                            signature_info["document_hash"] = document_hash.encode('utf-8', errors='ignore')
                            else:
                                signature_info["document_hash"] = str(document_hash).encode('utf-8', errors='ignore')

                        if "/DigestMethod" in field:
                            digest_method = field["/DigestMethod"]
                            if isinstance(digest_method, str):
                                signature_info["digest_method"] = digest_method[1:] if digest_method.startswith('/') else digest_method

                        if "/Name" in field:
                            signature_info["name"] = field["/Name"]
                        if "/M" in field:
                            signature_info["timestamp"] = field["/M"]

                        return signature_info

            print("No signature found in fields.")
            return None
        except Exception as e:
            print(f"Error extracting signature from PDF: {e}")
            return None
