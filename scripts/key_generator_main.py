"""
Entrypoint for the Key Generator application.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_generator.main import main

if __name__ == "__main__":
    main()