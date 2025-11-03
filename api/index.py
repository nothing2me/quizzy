"""
Vercel serverless function handler for FastAPI application.
This file serves as the entry point for Vercel serverless functions.
"""

import sys
import os

# Add parent directory to path so we can import main
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

# Change to parent directory to ensure relative imports work
os.chdir(parent_dir)

# Import the FastAPI app
from main import app

# Handler for Vercel - FastAPI is ASGI compatible
handler = app

