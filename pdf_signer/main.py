"""
Main entry point for the PDF document signing application.

This module initializes and launches the main GUI application.
"""

import sys
import platform
from common.utils.qt_fix import fix_qt_plugin_path

fix_qt_plugin_path()

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from .gui.main_window import PDFSignerMainWindow


def main():
    """
    Entry point for the PDF signing application.

    This function initializes the Qt application and shows the main window.
    It also applies platform-specific configurations.
    """
    if platform.system() == "Darwin":
        QApplication.setAttribute(Qt.AA_DontUseNativeDialogs, True)
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)

    app = QApplication(sys.argv)
    window = PDFSignerMainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
