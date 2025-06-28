#!/usr/bin/env python3
"""
SentrySearch Application Launcher

Supports both organized structure (src/) and legacy flat structure.
"""

import sys
import os

# Add src directory to Python path if it exists
src_path = os.path.join(os.path.dirname(__file__), 'src')
if os.path.exists(src_path):
    sys.path.insert(0, src_path)

# Try to import from src/ui/ first, then fall back to src/
try:
    from ui.app import create_ui
except ImportError:
    # Fallback to src/ for legacy compatibility
    try:
        from app import create_ui
    except ImportError:
        # Final fallback to root level
        sys.path.insert(0, os.path.dirname(__file__))
        from app import create_ui

if __name__ == "__main__":
    create_ui()