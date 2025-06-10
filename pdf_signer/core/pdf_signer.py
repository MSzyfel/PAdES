"""
Module for signing PDF documents.

This module implements the PDF signing functions used by the main application.
"""

import os
import io
import hashlib
import base64
from datetime import datetime
from typing import Optional, Tuple

from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import DictionaryObject, NameObject, ArrayObject, createStringObject, NumberObject, ByteStringObject

from common.crypto.rsa import sign_data
from common.utils.config import HASH_ALGORITHM, SIGNED_PDF_SUFFIX, PDF_EXTENSION
from ..models.signature import Signature


class PDFSigner:
    """
    Class for signing PDF documents.
    """

    def __init__(self, private_key: bytes):
        """
        Initializes the PDF signing object.

        :param private_key: RSA private key in PEM format.
        """
        self.private_key = private_key

    def sign_pdf(self, pdf_path: str, signer_name: str) -> Tuple[bool, str]:
        """
        Signs a PDF document.

        :param pdf_path: Path to the PDF document.
        :param signer_name: Name of the signer.
        :return: Tuple(success flag, path to signed document).
        """
        try:
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()

            hash_obj = hashlib.new(HASH_ALGORITHM)
            hash_obj.update(pdf_data)
            pdf_hash = hash_obj.digest()

            signature_data = sign_data(pdf_hash, self.private_key)

            signature = Signature(
                signature_data=signature_data,
                signer_name=signer_name,
                timestamp=datetime.now(),
                document_hash=pdf_hash,
            )

            signed_pdf_data = self._add_signature_to_pdf(pdf_data, signature)

            base_name, _ = os.path.splitext(pdf_path)
            signed_pdf_path = f"{base_name}{SIGNED_PDF_SUFFIX}{PDF_EXTENSION}"
            with open(signed_pdf_path, 'wb') as f:
                f.write(signed_pdf_data)

            with open(signed_pdf_path, 'rb') as f:
                signed_pdf_data = f.read()
            reader = PdfReader(io.BytesIO(signed_pdf_data))
            if "/AcroForm" in reader.trailer["/Root"]:
                acroform = reader.trailer["/Root"]["/AcroForm"]
                if "/Fields" in acroform:
                    fields = acroform["/Fields"]
                    for field in fields:
                        if isinstance(field, DictionaryObject) and "/Type" in field and field["/Type"] == "/Sig":
                            print("Signature was successfully added to the PDF document.")
                            break
                    else:
                        print("Warning: No signature found in the AcroForm fields.")
                else:
                    print("Warning: AcroForm does not contain Fields.")
            else:
                print("Warning: Document does not contain an AcroForm.")

            return True, signed_pdf_path
        except Exception as e:
            print(f"Error while signing PDF document: {e}")
            return False, ""

    def _add_signature_to_pdf(self, pdf_data: bytes, signature: Signature) -> bytes:
        """
        Adds a signature to the PDF document.

        :param pdf_data: PDF document data.
        :param signature: Signature object.
        :return: Data of the signed PDF document.
        """
        reader = PdfReader(io.BytesIO(pdf_data))
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        document_hash_base64 = base64.b64encode(signature.document_hash)

        sig_dict = DictionaryObject({
            NameObject("/Type"): NameObject("/Sig"),
            NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
            NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
            NameObject("/Name"): createStringObject(signature.signer_name),
            NameObject("/M"): createStringObject(signature.timestamp.strftime("D:%Y%m%d%H%M%S")),
            NameObject("/Contents"): ByteStringObject(signature.signature_data),
            NameObject("/ByteRange"): ArrayObject([NumberObject(0), NumberObject(0), NumberObject(0), NumberObject(0)]),
            NameObject("/DocumentHash"): ByteStringObject(document_hash_base64),
            NameObject("/DigestMethod"): NameObject(f"/{HASH_ALGORITHM.upper()}"),
            NameObject("/DocumentHashEncoding"): NameObject("/BASE64"),
        })

        if "/AcroForm" not in writer._root_object:
            writer._root_object[NameObject("/AcroForm")] = DictionaryObject({
                NameObject("/SigFlags"): NumberObject(3),
                NameObject("/Fields"): ArrayObject([sig_dict]),
            })
        else:
            acroform = writer._root_object["/AcroForm"]
            if "/Fields" in acroform:
                fields = acroform["/Fields"]
                fields.append(sig_dict)
            else:
                acroform[NameObject("/Fields")] = ArrayObject([sig_dict])
            acroform[NameObject("/SigFlags")] = NumberObject(3)

        output_stream = io.BytesIO()
        writer.write(output_stream)
        return output_stream.getvalue()
