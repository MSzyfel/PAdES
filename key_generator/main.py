"""
Main module of the helper application for generating RSA keys.

This module implements the entry point of the helper application for RSA key generation.
"""

import sys
from common.utils.qt_fix import fix_qt_plugin_path

fix_qt_plugin_path()

from PyQt5.QtWidgets import QApplication

from .gui.main_window import KeyGeneratorMainWindow


def main():
    """
    Entry point of the helper application for generating RSA keys.
    """
    app = QApplication(sys.argv)
    window = KeyGeneratorMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
