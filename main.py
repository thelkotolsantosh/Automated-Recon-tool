#!/usr/bin/env python3
"""
Run this from the project root:
  python main.py -t example.com --all
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from recon.main import main

if __name__ == "__main__":
    main()
