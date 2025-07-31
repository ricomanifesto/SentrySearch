#!/usr/bin/env python3
"""
SentrySearch Application Launcher

This script launches the SentrySearch Gradio application from the organized project structure.
"""

import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the main application
from ui.app import create_ui

if __name__ == "__main__":
    create_ui()