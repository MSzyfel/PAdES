"""
Entrypoint for the PDF Signer application.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pdf_signer.main import main

if __name__ == "__main__":
    main()