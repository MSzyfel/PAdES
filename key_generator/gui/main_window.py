"""
GUI module for the helper application that generates RSA keys.

This module implements the main window of the RSA key generator.
"""

import os
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QFileDialog, QMessageBox, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from common.usb.detector import get_usb_drives
from common.usb.storage import get_default_public_key_path
from common.utils.config import (
    APP_NAME, WINDOW_WIDTH, WINDOW_HEIGHT, WINDOW_TITLE,
    MSG_KEY_GENERATION_SUCCESS, MSG_KEY_GENERATION_FAILURE,
    MSG_PRIVATE_KEY_SAVED, MSG_PUBLIC_KEY_SAVED
)
from ..core.key_generator import KeyGenerator


class KeyGenerationThread(QThread):
    """
    Thread for RSA key generation.
    """
    finished = pyqtSignal(bool, str)

    def __init__(self, pin: str, drive_path: str, public_key_path: str):
        """
        Initializes the key generation thread.

        @param pin: User PIN.
        @param drive_path: Path to the USB drive.
        @param public_key_path: Path to the public key file.
        """
        super().__init__()
        self.pin = pin
        self.drive_path = drive_path
        self.public_key_path = public_key_path

    def run(self):
        """
        Starts RSA key generation in a separate thread.
        """
        try:
            generator = KeyGenerator()
            generator.generate_keys()
            generator.encrypt_private_key(self.pin)
            private_saved, public_saved = generator.save_keys(
                self.drive_path, self.public_key_path
            )

            if private_saved and public_saved:
                self.finished.emit(True, "Keys were generated and saved successfully.")
            elif private_saved:
                self.finished.emit(False, "Private key saved, but saving the public key failed.")
            elif public_saved:
                self.finished.emit(False, "Public key saved, but saving the private key failed.")
            else:
                self.finished.emit(False, "Failed to save both keys.")
        except Exception as e:
            self.finished.emit(False, f"An error occurred: {e}")


class KeyGeneratorMainWindow(QMainWindow):
    """
    Main window for the RSA key generator application.
    """

    def __init__(self):
        """
        Initializes the main window.
        """
        super().__init__()
        self.setWindowTitle(WINDOW_TITLE)
        self.setFixedSize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.init_ui()

    def init_ui(self):
        """
        Sets up the user interface.
        """
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setAlignment(Qt.AlignCenter)

        title_label = QLabel("RSA Key Generator")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        main_layout.addWidget(title_label)

        pin_layout = QHBoxLayout()
        pin_label = QLabel("PIN:")
        self.pin_input = QLineEdit()
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.setPlaceholderText("Enter PIN (min. 4 characters)")
        pin_layout.addWidget(pin_label)
        pin_layout.addWidget(self.pin_input)
        main_layout.addLayout(pin_layout)

        confirm_layout = QHBoxLayout()
        confirm_label = QLabel("Confirm PIN:")
        self.confirm_pin_input = QLineEdit()
        self.confirm_pin_input.setEchoMode(QLineEdit.Password)
        self.confirm_pin_input.setPlaceholderText("Confirm your PIN")
        confirm_layout.addWidget(confirm_label)
        confirm_layout.addWidget(self.confirm_pin_input)
        main_layout.addLayout(confirm_layout)

        drive_layout = QHBoxLayout()
        drive_label = QLabel("USB Drive:")
        self.drive_combo = QComboBox()
        self.refresh_drives()
        drive_refresh_button = QPushButton("Refresh")
        drive_refresh_button.clicked.connect(self.refresh_drives)
        drive_layout.addWidget(drive_label)
        drive_layout.addWidget(self.drive_combo)
        drive_layout.addWidget(drive_refresh_button)
        main_layout.addLayout(drive_layout)

        pubkey_layout = QHBoxLayout()
        pubkey_label = QLabel("Public Key:")
        self.public_key_input = QLineEdit()
        self.public_key_input.setText(get_default_public_key_path())
        pubkey_browse_button = QPushButton("Browse")
        pubkey_browse_button.clicked.connect(self.browse_public_key)
        pubkey_layout.addWidget(pubkey_label)
        pubkey_layout.addWidget(self.public_key_input)
        pubkey_layout.addWidget(pubkey_browse_button)
        main_layout.addLayout(pubkey_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        button_layout = QHBoxLayout()
        self.generate_button = QPushButton("Generate Keys")
        self.generate_button.clicked.connect(self.generate_keys)
        button_layout.addWidget(self.generate_button)
        main_layout.addLayout(button_layout)

    def refresh_drives(self):
        """
        Updates the list of available USB drives.
        """
        self.drive_combo.clear()
        drives = get_usb_drives()
        if drives:
            for drive in drives:
                self.drive_combo.addItem(drive)
        else:
            self.drive_combo.addItem("No USB drives available")

    def browse_public_key(self):
        """
        Opens a dialog to choose where to save the public key.
        """
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Public Key", get_default_public_key_path(),
            "PEM Files (*.pem);;All Files (*)"
        )
        if file_path:
            self.public_key_input.setText(file_path)

    def generate_keys(self):
        """
        Validates input and starts RSA key generation.
        """
        pin = self.pin_input.text()
        confirm_pin = self.confirm_pin_input.text()

        if len(pin) < 4:
            QMessageBox.warning(self, "Error", "PIN must be at least 4 characters long.")
            return
        if pin != confirm_pin:
            QMessageBox.warning(self, "Error", "PINs do not match.")
            return

        drive_path = self.drive_combo.currentText()
        if drive_path == "No USB drives available":
            QMessageBox.warning(self, "Error", "No USB drive selected.")
            return

        public_key_path = self.public_key_input.text()
        if not public_key_path:
            QMessageBox.warning(self, "Error", "Please select a public key file path.")
            return

        confirm = QMessageBox.question(
            self, "Confirm",
            "Are you sure you want to generate an RSA key pair?\n\n"
            f"Private key will be saved to USB: {drive_path}\n"
            f"Public key will be saved to: {public_key_path}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if confirm == QMessageBox.No:
            return

        self.progress_bar.setVisible(True)
        self.generate_button.setEnabled(False)

        self.thread = KeyGenerationThread(pin, drive_path, public_key_path)
        self.thread.finished.connect(self.on_key_generation_finished)
        self.thread.start()

    def on_key_generation_finished(self, success: bool, message: str):
        """
        Called when the key generation thread finishes.

        @param success: True if everything went fine.
        @param message: User-facing message.
        """
        self.progress_bar.setVisible(False)
        self.generate_button.setEnabled(True)

        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.warning(self, "Error", message)
