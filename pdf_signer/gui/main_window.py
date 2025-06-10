"""
Main GUI module for the PDF signing application.

This module implements the main window of the PDF signing app.
"""

import os
from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QFileDialog, QMessageBox, QTabWidget, QFormLayout, QProgressBar, QTextEdit, QGroupBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon, QPixmap
from common.usb.detector import find_drive_with_key, register_callback, start_monitoring
from common.usb.storage import load_private_key, load_public_key
from common.crypto.aes import decrypt_private_key
from common.utils.config import APP_NAME, WINDOW_WIDTH, WINDOW_HEIGHT, WINDOW_TITLE, MSG_USB_DETECTED, MSG_USB_NOT_DETECTED, MSG_PRIVATE_KEY_LOADED, MSG_PRIVATE_KEY_DECRYPTED, MSG_DOCUMENT_SIGNED, MSG_SIGNATURE_VERIFIED, MSG_SIGNATURE_INVALID, MSG_DOCUMENT_MODIFIED
from ..core.pdf_signer import PDFSigner
from ..core.pdf_verifier import PDFVerifier


class LoadPrivateKeyThread(QThread):
    """
    Thread for loading the private key.
    """
    finished = pyqtSignal(bool, bytes)

    def __init__(self, drive_path: str):
        """
        Initializes the private key loading thread.

        @param drive_path Path to the USB drive.
        """
        super().__init__()
        self.drive_path = drive_path

    def run(self):
        """
        Runs the private key loading thread.
        """
        try:
            encrypted_key = load_private_key(self.drive_path)
            if encrypted_key:
                self.finished.emit(True, encrypted_key)
            else:
                self.finished.emit(False, b"")
        except Exception as e:
            print(f"Error loading private key: {e}")
            self.finished.emit(False, b"")


class SignPDFThread(QThread):
    """
    Thread for signing the PDF document.
    """
    finished = pyqtSignal(bool, str, str)

    def __init__(self, private_key: bytes, pdf_path: str, signer_name: str):
        """
        Initializes the PDF signing thread.

        @param private_key RSA private key in PEM format.
        @param pdf_path Path to the PDF document.
        @param signer_name Name of the signer.
        """
        super().__init__()
        self.private_key = private_key
        self.pdf_path = pdf_path
        self.signer_name = signer_name

    def run(self):
        """
        Runs the PDF signing thread.
        """
        try:
            signer = PDFSigner(self.private_key)
            success, signed_pdf_path = signer.sign_pdf(self.pdf_path, self.signer_name)
            if success:
                self.finished.emit(True, "Document signed successfully.", signed_pdf_path)
            else:
                self.finished.emit(False, "Error occurred during document signing.", "")
        except Exception as e:
            self.finished.emit(False, f"Error: {e}", "")


class VerifyPDFThread(QThread):
    """
    Thread for verifying the PDF signature.
    """
    finished = pyqtSignal(bool, str, dict)

    def __init__(self, public_key: bytes, pdf_path: str):
        """
        Initializes the PDF signature verification thread.

        @param public_key RSA public key in PEM format.
        @param pdf_path Path to the PDF document.
        """
        super().__init__()
        self.public_key = public_key
        self.pdf_path = pdf_path

    def run(self):
        """
        Runs the PDF signature verification thread.
        """
        try:
            verifier = PDFVerifier(self.public_key)
            is_valid, message, signature_info = verifier.verify_pdf(self.pdf_path)
            if signature_info is None:
                signature_info = {}
            self.finished.emit(is_valid, message, signature_info)
        except Exception as e:
            self.finished.emit(False, f"Error: {e}", {})


class PDFSignerMainWindow(QMainWindow):
    """
    Main window of the PDF signing application.
    """

    def __init__(self):
        """
        Initializes the main window of the PDF signing application.
        """
        super().__init__()
        self.setWindowTitle(WINDOW_TITLE)
        self.setFixedSize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.private_key = None
        self.public_key = None
        self.drive_path = None
        self.encrypted_private_key = None
        self.init_ui()
        self.init_usb_monitoring()

    def init_ui(self):
        """
        Initializes the user interface.
        """
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.tab_widget = QTabWidget()
        self.tab_sign = QWidget()
        self.tab_verify = QWidget()
        self.tab_widget.addTab(self.tab_sign, "Sign Document")
        self.tab_widget.addTab(self.tab_verify, "Verify Signature")
        main_layout.addWidget(self.tab_widget)

        self.init_sign_tab()
        self.init_verify_tab()

        status_layout = QHBoxLayout()
        self.status_label = QLabel("USB drive status: Not detected")
        self.status_label.setStyleSheet("color: red;")
        status_layout.addWidget(self.status_label)
        main_layout.addLayout(status_layout)

    def init_sign_tab(self):
        """
        Initializes the sign document tab.
        """
        layout = QVBoxLayout(self.tab_sign)

        document_group = QGroupBox("PDF Document")
        document_layout = QHBoxLayout(document_group)
        self.document_input = QLineEdit()
        self.document_input.setPlaceholderText("Select PDF document to sign")
        document_browse_button = QPushButton("Browse")
        document_browse_button.clicked.connect(self.browse_document)
        document_layout.addWidget(self.document_input)
        document_layout.addWidget(document_browse_button)
        layout.addWidget(document_group)

        signature_group = QGroupBox("Signer Name")
        signature_layout = QHBoxLayout(signature_group)
        self.signer_name_input = QLineEdit()
        self.signer_name_input.setPlaceholderText("Enter signer name")
        signature_layout.addWidget(self.signer_name_input)

        layout.addWidget(signature_group)

        pin_group = QGroupBox("PIN")
        pin_layout = QHBoxLayout(pin_group)
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setPlaceholderText("Enter PIN")
        pin_layout.addWidget(self.pin_input)
        layout.addWidget(pin_group)

        self.sign_progress_bar = QProgressBar()
        self.sign_progress_bar.setRange(0, 0)
        self.sign_progress_bar.setVisible(False)
        layout.addWidget(self.sign_progress_bar)

        self.sign_button = QPushButton("Sign Document")
        self.sign_button.clicked.connect(self.sign_document)
        self.sign_button.setEnabled(False)
        layout.addWidget(self.sign_button)

    def init_verify_tab(self):
        """
        Initializes the verify signature tab.
        """
        layout = QVBoxLayout(self.tab_verify)

        document_group = QGroupBox("PDF Document")
        document_layout = QHBoxLayout(document_group)
        self.verify_document_input = QLineEdit()
        self.verify_document_input.setPlaceholderText("Select PDF document to verify")
        verify_document_browse_button = QPushButton("Browse")
        verify_document_browse_button.clicked.connect(self.browse_verify_document)
        document_layout.addWidget(self.verify_document_input)
        document_layout.addWidget(verify_document_browse_button)
        layout.addWidget(document_group)

        public_key_group = QGroupBox("Public Key")
        public_key_layout = QHBoxLayout(public_key_group)
        self.public_key_input = QLineEdit()
        self.public_key_input.setPlaceholderText("Select public key")
        public_key_browse_button = QPushButton("Browse")
        public_key_browse_button.clicked.connect(self.browse_public_key)
        public_key_layout.addWidget(self.public_key_input)
        public_key_layout.addWidget(public_key_browse_button)
        layout.addWidget(public_key_group)

        self.verify_progress_bar = QProgressBar()
        self.verify_progress_bar.setRange(0, 0)
        self.verify_progress_bar.setVisible(False)
        layout.addWidget(self.verify_progress_bar)

        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.clicked.connect(self.verify_document)
        layout.addWidget(self.verify_button)

        result_group = QGroupBox("Verification Result")
        result_layout = QVBoxLayout(result_group)
        self.verify_result_text = QTextEdit()
        self.verify_result_text.setReadOnly(True)
        result_layout.addWidget(self.verify_result_text)
        layout.addWidget(result_group)

    def init_usb_monitoring(self):
        """
        Initializes USB device monitoring.
        """
        self.drive_path = find_drive_with_key()
        if self.drive_path:
            self.on_usb_detected(self.drive_path)

        register_callback(self.on_usb_detected)
        start_monitoring()

    @pyqtSlot(str)
    def on_usb_detected(self, drive_path: str):
        """
        Handles detection of USB drive with private key.

        @param drive_path Path to the USB drive.
        """
        self.drive_path = drive_path
        self.status_label.setText(f"USB drive status: Detected ({drive_path})")
        self.status_label.setStyleSheet("color: green;")
        self.sign_button.setEnabled(True)

        self.load_key_thread = LoadPrivateKeyThread(drive_path)
        self.load_key_thread.finished.connect(self.on_private_key_loaded)
        self.load_key_thread.start()

    @pyqtSlot(bool, bytes)
    def on_private_key_loaded(self, success: bool, encrypted_key: bytes):
        """
        Handles completion of private key loading.

        @param success Operation success status.
        @param encrypted_key Encrypted private key.
        """
        if success:
            self.encrypted_private_key = encrypted_key
            QMessageBox.information(self, "Success", MSG_PRIVATE_KEY_LOADED)
        else:
            QMessageBox.warning(self, "Error", "Failed to load private key.")

    def browse_document(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select PDF Document", "", "PDF Files (*.pdf);;All Files (*)")
        if file_path:
            self.document_input.setText(file_path)

    def browse_verify_document(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select PDF Document", "", "PDF Files (*.pdf);;All Files (*)")
        if file_path:
            self.verify_document_input.setText(file_path)

    def browse_public_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Public Key", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.public_key_input.setText(file_path)

    def sign_document(self):
        """
        Starts the document signing process.
        """
        if not self.drive_path or not self.encrypted_private_key:
            QMessageBox.warning(self, "Error", "USB drive or private key not available.")
            return

        pin = self.pin_input.text()
        if not pin:
            QMessageBox.warning(self, "Error", "Please enter the PIN.")
            return

        try:
            self.private_key = decrypt_private_key(self.encrypted_private_key, pin)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to decrypt private key: {e}")
            return

        pdf_path = self.document_input.text()
        if not os.path.isfile(pdf_path):
            QMessageBox.warning(self, "Error", "Invalid PDF document path.")
            return

        signer_name = self.signer_name_input.text()
        if not signer_name:
            QMessageBox.warning(self, "Error", "Signer name is required.")
            return


        self.sign_progress_bar.setVisible(True)
        self.sign_button.setEnabled(False)

        self.sign_thread = SignPDFThread(self.private_key, pdf_path, signer_name)
        self.sign_thread.finished.connect(self.on_sign_finished)
        self.sign_thread.start()

    @pyqtSlot(bool, str, str)
    def on_sign_finished(self, success: bool, message: str, signed_pdf_path: str):
        """
        Handles the result of the document signing process.

        @param success Operation success status.
        @param message Status message.
        @param signed_pdf_path Path to the signed PDF document.
        """
        self.sign_progress_bar.setVisible(False)
        self.sign_button.setEnabled(True)

        if success:
            QMessageBox.information(self, "Success", message)
            self.document_input.setText(signed_pdf_path)
        else:
            QMessageBox.warning(self, "Error", message)

    def verify_document(self):
        """
        Starts the signature verification process.
        """
        pdf_path = self.verify_document_input.text()
        if not os.path.isfile(pdf_path):
            QMessageBox.warning(self, "Error", "Invalid PDF document path.")
            return

        public_key_path = self.public_key_input.text()
        if not os.path.isfile(public_key_path):
            QMessageBox.warning(self, "Error", "Invalid public key path.")
            return

        try:
            with open(public_key_path, "rb") as f:
                self.public_key = f.read()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load public key: {e}")
            return

        self.verify_progress_bar.setVisible(True)
        self.verify_button.setEnabled(False)

        self.verify_thread = VerifyPDFThread(self.public_key, pdf_path)
        self.verify_thread.finished.connect(self.on_verify_finished)
        self.verify_thread.start()

    @pyqtSlot(bool, str, dict)
    def on_verify_finished(self, valid: bool, message: str, signature_info: dict):
        """
        Handles the result of the signature verification.

        @param valid Verification status.
        @param message Status message.
        @param signature_info Details about the signature.
        """
        self.verify_progress_bar.setVisible(False)
        self.verify_button.setEnabled(True)

        result_text = f"{message}\n\n"
        if signature_info:
            for key, value in signature_info.items():
                result_text += f"{key}: {value}\n"

        self.verify_result_text.setPlainText(result_text)
        if valid:
            QMessageBox.information(self, "Verification", MSG_SIGNATURE_VERIFIED)
        else:
            QMessageBox.warning(self, "Verification", MSG_SIGNATURE_INVALID)
