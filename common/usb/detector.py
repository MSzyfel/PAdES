import ctypes
import os
import platform
import string
import time
from typing import List, Optional, Callable

from PyQt5.QtCore import QObject, pyqtSignal
from ..utils.config import PRIVATE_KEY_FILENAME


class USBDetectorSignals(QObject):
    """
    Signal class for USB detector.
    """
    drive_detected = pyqtSignal(str)


class USBDetector(QObject):
    """
    USB device detector.
    """

    def __init__(self):
        super().__init__()
        self.system = platform.system()
        self.usb_drives = []
        self.callbacks = []
        self.signals = USBDetectorSignals()
        self.last_detected_drive = None

    def get_usb_drives(self) -> List[str]:
        """
        Returns a list of paths to connected USB devices.
        """
        if self.system == "Windows":
            return self._get_usb_drives_windows()
        elif self.system == "Darwin":
            return self._get_usb_drives_macos()
        else:
            return self._get_usb_drives_linux()

    def _get_usb_drives_windows(self) -> List[str]:
        """
        Returns a list of USB device paths on Windows.
        """
        try:
            return [f"{l}:\\" for l in string.ascii_uppercase if
                    os.path.exists(f"{l}:\\") and ctypes.windll.kernel32.GetDriveTypeW(f"{l}:\\") == 2]
        except Exception as e:
            print(f"Error detecting USB on Windows: {e}")
            return []

    def _get_usb_drives_windows_wmi(self) -> List[str]:
        """
        Alternate method using WMI to detect USB drives on Windows.
        """
        drives = []
        try:
            import wmi
            c = wmi.WMI()
            for d in c.Win32_LogicalDisk():
                if d.DriveType in [2, 3]:
                    p = f"{d.DeviceID}\\"
                    try:
                        os.listdir(p)
                        drives.append(p)
                        print(f"WMI detected: {p} (type: {d.DriveType})")
                    except:
                        print(f"No access: {p}")
        except ImportError:
            print("Install WMI: pip install WMI")
        except Exception as e:
            print(f"WMI error: {e}")
        return drives

    def _get_usb_drives_macos(self) -> List[str]:
        """
        Returns USB device paths on macOS.
        """
        base = "/Volumes"
        return [os.path.join(base, v) for v in os.listdir(base)
                if os.path.ismount(os.path.join(base, v))] if os.path.exists(base) else []

    def _get_usb_drives_linux(self) -> List[str]:
        """
        Returns USB device paths on Linux.
        """
        base = "/media"
        drives = []
        if os.path.exists(base):
            for user in os.listdir(base):
                user_path = os.path.join(base, user)
                if os.path.isdir(user_path):
                    for volume in os.listdir(user_path):
                        vp = os.path.join(user_path, volume)
                        if os.path.ismount(vp):
                            drives.append(vp)
        return drives

    def find_drive_with_key(self) -> Optional[str]:
        """
        Finds a USB drive containing the private key.
        """
        for drive in self.get_usb_drives():
            path = os.path.join(drive, PRIVATE_KEY_FILENAME)
            if os.path.exists(path):
                print(f"Key found on: {drive}")
                return drive
        return None

    def register_callback(self, callback: Callable[[str], None]) -> None:
        """
        Registers a callback to be called when a drive is detected.
        """
        self.callbacks.append(callback)
        self.signals.drive_detected.connect(callback)

    def start_monitoring(self) -> None:
        """
        Starts monitoring for new USB devices.
        """
        import threading

        def monitor():
            while True:
                drive = self.find_drive_with_key()
                if drive and drive != self.last_detected_drive:
                    self.last_detected_drive = drive
                    print(f"Drive detected: {drive}")
                    self.signals.drive_detected.emit(drive)
                time.sleep(1)

        threading.Thread(target=monitor, daemon=True).start()


# Singleton
detector = USBDetector()


def get_usb_drives() -> List[str]:
    return detector.get_usb_drives()


def find_drive_with_key() -> Optional[str]:
    return detector.find_drive_with_key()


def register_callback(callback: Callable[[str], None]) -> None:
    detector.register_callback(callback)


def start_monitoring() -> None:
    detector.start_monitoring()
