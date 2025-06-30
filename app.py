#!/usr/bin/env python3
"""
Entry point for Hugging Face Spaces deployment
"""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the main application
from src.ui.app import create_ui

if __name__ == "__main__":
    create_ui()