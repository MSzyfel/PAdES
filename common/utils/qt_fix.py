"""
Qt platform plugin fix for macOS.

This module provides a utility function to fix Qt platform plugin issues
on macOS by setting the correct QT_QPA_PLATFORM_PLUGIN_PATH.
"""

import os
import sys


def fix_qt_plugin_path():
    """
    Fix Qt platform plugin path for macOS.
    
    This function must be called before importing any PyQt5 modules
    to prevent "Could not find the Qt platform plugin 'cocoa'" error.
    """
    if sys.platform == 'darwin':
        try:
            import PyQt5
            qt_dir = os.path.dirname(PyQt5.__file__)
            
            possible_paths = [
                os.path.join(qt_dir, 'Qt5', 'plugins'),
                os.path.join(qt_dir, 'Qt', 'plugins'),
                os.path.join(qt_dir, 'plugins'),
            ]
            
            for path in possible_paths:
                if os.path.exists(path) and os.path.exists(os.path.join(path, 'platforms')):
                    os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = path
                    print(f"QT_QPA_PLATFORM_PLUGIN_PATH set to: {path}")
                    return True
            else:
                print("Could not find a valid Qt plugin path.")
                return False
                
        except ImportError:
            print("PyQt5 is not installed. Please install it to run the application.")
            return False
    
    return True  # Not macOS, no fix needed