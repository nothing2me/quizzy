"""
Vercel serverless function handler for FastAPI application.
This file serves as the entry point for Vercel serverless functions.
"""

import sys
import os

# Add parent directory to path so we can import main
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Change to parent directory to ensure relative imports work
os.chdir(parent_dir)

# Import the FastAPI app
try:
    from main import app
except Exception as e:
    # If import fails, provide a helpful error
    import traceback
    print(f"Error importing main: {e}")
    print(traceback.format_exc())
    raise

# Wrap FastAPI app with Mangum for Vercel/AWS Lambda compatibility
from mangum import Mangum

# Create Mangum handler - this wraps the ASGI app for serverless
# lifespan="off" because we handle initialization in main.py
handler = Mangum(app, lifespan="off")

