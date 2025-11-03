"""
Entry point for the Quizzy collaborative flashcard web application using FastAPI.

This module defines the FastAPI application, configures session
handling, sets up the SQLite database, and implements routes for
registration, authentication, set management, flashcard CRUD
operations, and collaborator management. The application uses
Jinja2 templates stored in the ``templates`` directory to render
HTML pages and stores session data in signed cookies via
Starlette's ``SessionMiddleware``. Database operations are performed
using Python's built-in ``sqlite3`` module without relying on
external ORM libraries.
"""

from __future__ import annotations

import os
import sqlite3
from urllib.parse import parse_qs
from typing import Any, Dict, List, Optional, Tuple
from contextlib import asynccontextmanager
from quizlet_importer import QuizletImporter

from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

# Import security modules
from security import (
    SecurePasswordManager, 
    AccountLockoutManager, 
    InputValidator,
    rate_limit_login,
    rate_limit_signup,
    add_security_headers_middleware,
    setup_security_error_handlers,
    generate_secure_token
)

# Define the path where the SQLite database will be stored. We store
# it alongside this script for simplicity. When running inside a
# container, this will persist under the shared volume.
# For Vercel, use /tmp directory (ephemeral storage)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Check if running on Vercel (serverless environment)
if os.environ.get("VERCEL"):
    # Vercel provides ephemeral /tmp directory
    DATABASE_PATH = "/tmp/flashcards.db"
else:
    # Local development - use project directory
    DATABASE_PATH = os.path.join(BASE_DIR, "flashcards.db")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events."""
    # Startup
    try:
        init_db()
    except Exception as e:
        # Log error but don't fail startup
        print(f"Warning: Database initialization error: {e}")
    yield
    # Shutdown (if needed)
    pass


app = FastAPI(lifespan=lifespan)

# Session store. For Vercel/serverless, we need to use a persistent solution.
# In-memory sessions won't work across function invocations.
# For production, consider Redis or database-backed sessions.
# For now, using in-memory with a note that it won't persist on Vercel.
if os.environ.get("VERCEL"):
    # On Vercel, in-memory sessions won't persist between invocations
    # Consider using environment variables or external session store
    app.state.sessions = {}
    # TODO: Implement Redis or database-backed sessions for production
else:
    # In-memory session store for local development
    app.state.sessions = {}

# Configure Jinja2 templates. Templates are located in the templates
# directory relative to this file. We also set auto-reload to true
# during development so template changes are picked up without
# restarting the server.
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# ---------------------------------------------------------------------------
# Database utilities
# ---------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    """Return a singleton SQLite3 connection.

    We create a single connection and reuse it across requests to avoid
    the overhead of opening and closing connections repeatedly. The
    ``check_same_thread`` flag is set to False so the connection can
    safely be used by FastAPI's default thread pool executor.
    """
    if not hasattr(app.state, "_db_conn"):
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable foreign key enforcement
        conn.execute("PRAGMA foreign_keys = ON")
        app.state._db_conn = conn
    return app.state._db_conn


def init_db() -> None:
    """Create database tables if they do not already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked_until DATETIME,
            email TEXT,
            email_verified BOOLEAN DEFAULT 0,
            is_admin BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1
        );
        
        CREATE TABLE IF NOT EXISTS flashcard_set (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            public INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            version INTEGER DEFAULT 1,
            FOREIGN KEY (owner_id) REFERENCES user(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS flashcard (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            set_id INTEGER NOT NULL,
            front TEXT NOT NULL,
            back TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            version INTEGER DEFAULT 1,
            created_by INTEGER,
            updated_by INTEGER,
            FOREIGN KEY (set_id) REFERENCES flashcard_set(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES user(id),
            FOREIGN KEY (updated_by) REFERENCES user(id)
        );

        CREATE TABLE IF NOT EXISTS set_collaborator (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            set_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'editor',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (set_id) REFERENCES flashcard_set(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
            UNIQUE(set_id, user_id)
        );
        
        CREATE TABLE IF NOT EXISTS security_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE SET NULL
        );
        
        -- Add indexes for performance
        CREATE INDEX IF NOT EXISTS idx_user_username ON user(username);
        CREATE INDEX IF NOT EXISTS idx_user_email ON user(email);
        CREATE INDEX IF NOT EXISTS idx_flashcard_set_owner ON flashcard_set(owner_id);
        CREATE INDEX IF NOT EXISTS idx_flashcard_set_public ON flashcard_set(public);
        CREATE INDEX IF NOT EXISTS idx_flashcard_set_id ON flashcard(set_id);
        CREATE INDEX IF NOT EXISTS idx_collaborator_set_id ON set_collaborator(set_id);
        CREATE INDEX IF NOT EXISTS idx_collaborator_user_id ON set_collaborator(user_id);
        CREATE INDEX IF NOT EXISTS idx_security_log_user_id ON security_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_security_log_event_type ON security_log(event_type);
        """
    )
    conn.commit()


# Add security middleware
add_security_headers_middleware(app)
setup_security_error_handlers(app)


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Return a secure bcrypt hash of the provided password.
    
    Uses bcrypt with automatic salt generation for production-grade security.
    """
    return SecurePasswordManager.hash_password(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify that a plaintext password matches the stored hash."""
    return SecurePasswordManager.verify_password(password, password_hash)


# ---------------------------------------------------------------------------
# User and session management
# ---------------------------------------------------------------------------

def get_current_user(request: Request) -> Optional[sqlite3.Row]:
    """Retrieve the currently authenticated user from a signed cookie.

    Sessions are stored in ``app.state.sessions`` keyed by a
    ``session_id`` cookie. If no cookie exists or the session ID is
    unknown, return None.
    """
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    user_id = app.state.sessions.get(session_id)
    if user_id is None:
        return None
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    return row


def require_login(request: Request) -> sqlite3.Row:
    """Dependency that raises an HTTP exception if the user is not authenticated."""
    user = get_current_user(request)
    if user is None:
        # Redirect to login page if unauthenticated
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": str(request.url_for("login_get"))},
        )
    return user


def require_admin(request: Request) -> sqlite3.Row:
    """Dependency that raises an HTTP exception if the user is not an admin."""
    user = get_current_user(request)
    if user is None:
        # Redirect to login page if not authenticated
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": str(request.url_for("login_get"))},
        )
    if not user["is_admin"]:
        # Redirect to dashboard if not admin
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": str(request.url_for("index"))},
        )
    return user


def check_admin_access(request: Request) -> sqlite3.Row:
    """Check admin access and return user or redirect with flash message."""
    user = get_current_user(request)
    if user is None:
        # Redirect to login page if not authenticated
        response = RedirectResponse(str(request.url_for("login_get")), status_code=302)
        response.set_cookie("flash_message", "Please log in to access the admin panel.", max_age=5)
        response.set_cookie("flash_type", "warning", max_age=5)
        return response
    if not user["is_admin"]:
        # Redirect to dashboard if not admin
        response = RedirectResponse(str(request.url_for("index")), status_code=302)
        response.set_cookie("flash_message", "Access denied. Admin privileges required.", max_age=5)
        response.set_cookie("flash_type", "danger", max_age=5)
        return response
    return user


# ---------------------------------------------------------------------------
# Quizlet Import Routes
# ---------------------------------------------------------------------------

@app.get("/import-quizlet")
def import_quizlet_get(request: Request):
    """Display Quizlet import form"""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(str(request.url_for("login_get")), status_code=302)
    
    return templates.TemplateResponse("import_quizlet.html", {
        "request": request,
        "user": user,
    })


@app.post("/import-quizlet")
async def import_quizlet_post(request: Request):
    """Handle Quizlet import with comprehensive error handling"""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(str(request.url_for("login_get")), status_code=302)
    
    try:
        form_data = await request.form()
        
        # Extract form data
        quizlet_url = form_data.get("quizlet_url", "").strip()
        import_text = form_data.get("import_text", "").strip()
        set_name = form_data.get("set_name", "").strip()
        is_public = form_data.get("is_public") == "on"
        import_method = form_data.get("import_method", "url")
        
        # Handle CSV file upload
        csv_file = None
        if import_method == "csv":
            csv_file = form_data.get("csv_file")
            if not csv_file or csv_file.filename == "":
                return templates.TemplateResponse("import_quizlet.html", {
                    "request": request,
                    "user": user,
                    "error": "Please select a CSV file to upload",
                    "form_data": {"set_name": set_name, "is_public": is_public}
                })
        
        # Validate inputs
        if not quizlet_url and not import_text and not csv_file:
            return templates.TemplateResponse("import_quizlet.html", {
                "request": request,
                "user": user,
                "error": "Please provide either a Quizlet URL, paste exported text, or upload a CSV file",
                "form_data": {"set_name": set_name, "is_public": is_public}
            })
        
        if not set_name:
            set_name = "Imported Quizlet Set"
        
        flashcards = []
        title = set_name
        
        # Handle CSV import
        if csv_file and import_method == "csv":
            try:
                # Read CSV file content
                csv_content = await csv_file.read()
                csv_text = csv_content.decode('utf-8')
                
                flashcards = parse_csv_content(csv_text)
                if not flashcards:
                    return templates.TemplateResponse("import_quizlet.html", {
                        "request": request,
                        "user": user,
                        "error": "No valid flashcards found in the CSV file. Make sure the file has at least 2 columns (term and definition).",
                        "form_data": {"set_name": set_name, "is_public": is_public}
                    })
            except Exception as e:
                return templates.TemplateResponse("import_quizlet.html", {
                    "request": request,
                    "user": user,
                    "error": f"Error reading CSV file: {str(e)}",
                    "form_data": {"set_name": set_name, "is_public": is_public}
                })
        
        # Handle text import (manual Quizlet export)
        elif import_text and import_method == "text":
            flashcards = parse_quizlet_text(import_text)
            if not flashcards:
                return templates.TemplateResponse("import_quizlet.html", {
                    "request": request,
                    "user": user,
                    "error": "No valid flashcards found in the text. Make sure each line has a term and definition separated by a tab.",
                    "form_data": {"set_name": set_name, "is_public": is_public, "import_text": import_text}
                })
        
        # Handle URL import
        elif quizlet_url and import_method == "url":
            importer = QuizletImporter()
            if not importer.validate_quizlet_url(quizlet_url):
                return templates.TemplateResponse("import_quizlet.html", {
                    "request": request,
                    "user": user,
                    "error": "Invalid Quizlet URL format",
                    "form_data": {"set_name": set_name, "is_public": is_public, "quizlet_url": quizlet_url}
                })
            
            extracted_title, extracted_flashcards, message = importer.import_from_url(quizlet_url)
            
            if extracted_flashcards:
                flashcards = extracted_flashcards
                if not set_name or set_name == "Imported Quizlet Set":
                    title = extracted_title
            else:
                return templates.TemplateResponse("import_quizlet.html", {
                    "request": request,
                    "user": user,
                    "error": f"Could not extract flashcards from URL. {message}",
                    "form_data": {"set_name": set_name, "is_public": is_public, "quizlet_url": quizlet_url},
                    "show_text_fallback": True
                })
        
        # Create the flashcard set
        if flashcards:
            set_id = create_flashcard_set(title, flashcards, user["id"], is_public)
            
            # Redirect to the new set with success message
            response = RedirectResponse(
                str(request.url_for("view_set", set_id=set_id)),
                status_code=302
            )
            response.set_cookie("flash_message", f"Successfully imported {len(flashcards)} flashcards!", max_age=5)
            response.set_cookie("flash_type", "success", max_age=5)
            return response
        
        return templates.TemplateResponse("import_quizlet.html", {
            "request": request,
            "user": user,
            "error": "No flashcards could be imported",
            "form_data": {"set_name": set_name, "is_public": is_public}
        })
        
    except Exception as e:
        return templates.TemplateResponse("import_quizlet.html", {
            "request": request,
            "user": user,
            "error": f"An unexpected error occurred: {str(e)}",
            "form_data": {"set_name": set_name, "is_public": is_public}
        })


def parse_quizlet_text(text: str) -> List[Dict]:
    """Parse Quizlet exported text into flashcards with multiple format support"""
    flashcards = []
    
    # First try semicolon-separated format
    if ';' in text and '\t' in text:
        cards = text.strip().split(';')
        
        for card_text in cards:
            card_text = card_text.strip()
            if not card_text:
                continue
                
            # Handle tab-separated format within each card
            if '\t' in card_text:
                parts = card_text.split('\t', 1)
                if len(parts) == 2:
                    front = parts[0].strip()
                    back = parts[1].strip()
                    if front and back and len(front) > 0 and len(back) > 5:  # Basic validation
                        flashcards.append({
                            'front': front,
                            'back': back
                        })
    
    # If no semicolons found or no cards parsed, try line-by-line format
    if not flashcards:
        lines = text.strip().split('\n')
        current_card = None
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
                
            # Skip lines that look like examples or data (contain only numbers/spaces/symbols)
            if line.replace(' ', '').replace('|', '').replace('-', '').replace(':', '').isdigit() or len(line.split()) <= 2:
                continue
                
            # Handle tab-separated format
            if '\t' in line:
                # If we have a current card, save it first
                if current_card and current_card['front'] and current_card['back']:
                    flashcards.append(current_card)
                
                parts = line.split('\t', 1)
                if len(parts) == 2:
                    front = parts[0].strip()
                    back = parts[1].strip()
                    # Basic validation: front should be meaningful, back should be substantial
                    if (front and back and 
                        len(front) > 0 and len(back) > 5 and 
                        not front.isdigit() and 
                        not (len(front) <= 3 and front.isalpha())):  # Skip single letters/numbers
                        current_card = {
                            'front': front,
                            'back': back
                        }
                    else:
                        current_card = None
            else:
                # This line doesn't have a tab, so it's likely a continuation of the previous definition
                if current_card and current_card['back']:
                    # Append this line to the current definition
                    current_card['back'] += '\n' + line
        
        # Don't forget to add the last card
        if current_card and current_card['front'] and current_card['back']:
            flashcards.append(current_card)
    
    return flashcards


def parse_csv_content(csv_content: str) -> List[Dict]:
    """Parse CSV content into flashcards with flexible format support"""
    import csv
    import io
    
    flashcards = []
    
    try:
        # Try to detect delimiter
        delimiter = ','
        if '\t' in csv_content and csv_content.count('\t') > csv_content.count(','):
            delimiter = '\t'
        elif ';' in csv_content and csv_content.count(';') > csv_content.count(','):
            delimiter = ';'
        
        # Create CSV reader
        csv_reader = csv.reader(io.StringIO(csv_content), delimiter=delimiter)
        
        # Skip header row if it looks like headers
        rows = list(csv_reader)
        if rows and len(rows) > 1:
            # Check if first row looks like headers (contains common header words)
            header_words = ['term', 'definition', 'front', 'back', 'question', 'answer', 'word', 'meaning']
            first_row_lower = ' '.join(rows[0]).lower()
            if any(word in first_row_lower for word in header_words):
                rows = rows[1:]  # Skip header row
        
        # Process each row
        for row_num, row in enumerate(rows, 1):
            if len(row) < 2:
                continue  # Skip rows with insufficient columns
            
            # Clean up the data
            front = row[0].strip()
            back = row[1].strip()
            
            # Basic validation
            if (front and back and 
                len(front) > 0 and len(back) > 2 and
                not front.isdigit() and
                not (len(front) <= 2 and front.isalpha())):  # Skip single letters/numbers
                flashcards.append({
                    'front': front,
                    'back': back
                })
    
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        # Fallback: try simple line-by-line parsing
        lines = csv_content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Try different delimiters
            for delim in [',', '\t', ';']:
                if delim in line:
                    parts = line.split(delim, 1)
                    if len(parts) == 2:
                        front = parts[0].strip().strip('"\'')
                        back = parts[1].strip().strip('"\'')
                        if front and back and len(front) > 0 and len(back) > 2:
                            flashcards.append({
                                'front': front,
                                'back': back
                            })
                    break
    
    return flashcards


def create_flashcard_set(name: str, flashcards: List[Dict], owner_id: int, is_public: bool) -> int:
    """Create a new flashcard set and return its ID"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Insert flashcard set
        cursor.execute(
            "INSERT INTO flashcard_set (name, owner_id, public) VALUES (?, ?, ?)",
            (name, owner_id, 1 if is_public else 0)
        )
        set_id = cursor.lastrowid
        
        # Insert flashcards
        for card in flashcards:
            cursor.execute(
                "INSERT INTO flashcard (set_id, front, back, created_by) VALUES (?, ?, ?, ?)",
                (set_id, card["front"], card["back"], owner_id)
            )
        
        conn.commit()
        return set_id
        
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Card Edit Routes
# ---------------------------------------------------------------------------

@app.get("/set/{set_id}/card/{card_id}/edit", name="edit_card")
def edit_card_get(request: Request, set_id: int, card_id: int):
    """Display edit card form"""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(str(request.url_for("login_get")), status_code=302)
    
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the card
    cursor.execute(
        "SELECT * FROM flashcard WHERE id = ? AND set_id = ?", (card_id, set_id)
    )
    card = cursor.fetchone()
    
    if not card:
        conn.close()
        return RedirectResponse(str(request.url_for("view_set", set_id=set_id)), status_code=302)
    
    # Check if user can edit this set
    cursor.execute(
        "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
    )
    flashcard_set = cursor.fetchone()
    
    if not flashcard_set:
        conn.close()
        return RedirectResponse(str(request.url_for("index")), status_code=302)
    
    # Check edit permissions
    can_edit = (
        flashcard_set["owner_id"] == user["id"] or
        (user.get("is_admin", False)) or
        can_edit_set(set_id, user["id"])
    )
    
    if not can_edit:
        conn.close()
        return RedirectResponse(str(request.url_for("view_set", set_id=set_id)), status_code=302)
    
    conn.close()
    
    return templates.TemplateResponse("edit_card.html", {
        "request": request,
        "user": user,
        "flashcard_set": flashcard_set,
        "card": card
    })


@app.post("/set/{set_id}/card/{card_id}/edit", name="edit_card_post")
async def edit_card_post(request: Request, set_id: int, card_id: int):
    """Handle card edit submission"""
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(str(request.url_for("login_get")), status_code=302)
    
    try:
        form_data = await request.form()
        front = form_data.get("front", "").strip()
        back = form_data.get("back", "").strip()
        
        if not front or not back:
            return templates.TemplateResponse("edit_card.html", {
                "request": request,
                "user": user,
                "flashcard_set": {"id": set_id},
                "card": {"id": card_id},
                "error": "Both term and definition are required"
            })
        
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Verify card exists and user can edit
        cursor.execute(
            "SELECT * FROM flashcard WHERE id = ? AND set_id = ?", (card_id, set_id)
        )
        card = cursor.fetchone()
        
        if not card:
            conn.close()
            return RedirectResponse(str(request.url_for("view_set", set_id=set_id)), status_code=302)
        
        # Check edit permissions
        cursor.execute(
            "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
        )
        flashcard_set = cursor.fetchone()
        
        can_edit = (
            flashcard_set["owner_id"] == user["id"] or
            (user.get("is_admin", False)) or
            can_edit_set(set_id, user["id"])
        )
        
        if not can_edit:
            conn.close()
            return RedirectResponse(str(request.url_for("view_set", set_id=set_id)), status_code=302)
        
        # Update the card
        cursor.execute(
            "UPDATE flashcard SET front = ?, back = ?, updated_by = ? WHERE id = ?",
            (front, back, user["id"], card_id)
        )
        
        conn.commit()
        conn.close()
        
        # Redirect back to set with success message
        response = RedirectResponse(
            str(request.url_for("view_set", set_id=set_id)),
            status_code=302
        )
        response.set_cookie("flash_message", "Card updated successfully!", max_age=5)
        response.set_cookie("flash_type", "success", max_age=5)
        return response
        
    except Exception as e:
        return templates.TemplateResponse("edit_card.html", {
            "request": request,
            "user": user,
            "flashcard_set": {"id": set_id},
            "card": {"id": card_id},
            "error": f"Error updating card: {str(e)}"
        })


# ---------------------------------------------------------------------------
# Learn Mode Routes
# ---------------------------------------------------------------------------

@app.get("/set/{set_id}/learn", name="learn_mode")
def learn_mode(request: Request, set_id: int, question: int = 1, direction: str = "def_to_term"):
    """Learn mode with definition and multiple choice questions - NO AUTH REQUIRED"""
    # Remove authentication requirement for learn mode
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get flashcard set
    cursor.execute(
        "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
    )
    flashcard_set = cursor.fetchone()
    
    if not flashcard_set:
        conn.close()
        return RedirectResponse(str(request.url_for("index")), status_code=302)
    
    # Get all flashcards for this set
    cursor.execute(
        "SELECT * FROM flashcard WHERE set_id = ? ORDER BY RANDOM()", (set_id,)
    )
    cards = cursor.fetchall()
    
    if not cards:
        conn.close()
        return templates.TemplateResponse("learn_mode.html", {
            "request": request,
            "user": None,  # No user required
            "flashcard_set": flashcard_set,
            "error": "No flashcards found in this set"
        })
    
    conn.close()
    
    # Convert to list and get current question
    cards_list = [dict(card) for card in cards]
    total_questions = len(cards_list)
    
    # Handle question bounds
    if question < 1:
        question = 1
    elif question > total_questions:
        question = total_questions
    
    current_card = cards_list[question - 1]
    
    # Determine prompt/answer direction
    direction = direction if direction in ("def_to_term", "term_to_def") else "def_to_term"

    # Generate randomized answer options
    import random
    
    # Get wrong answers from other cards
    other_cards = [card for card in cards_list if card['id'] != current_card['id']]
    
    # Create answer options
    correct_answer = current_card['front']
    wrong_answers = []
    
    if len(other_cards) >= 3:
        # Use 3 random wrong answers from other cards
        if direction == "def_to_term":
            wrong_answers = random.sample([card['front'] for card in other_cards], 3)
        else:
            wrong_answers = random.sample([card['back'] for card in other_cards], 3)
    else:
        # If not enough other cards, pad with generic options
        wrong_answers = [card['front'] for card in other_cards] if direction == "def_to_term" else [card['back'] for card in other_cards]
        while len(wrong_answers) < 3:
            wrong_answers.append(f"Option {len(wrong_answers) + 2}")
    
    # Choose correct answer based on direction
    if direction == "def_to_term":
        correct_answer = current_card['front']
    else:
        correct_answer = current_card['back']

    # Create all answers and randomize their positions
    all_answers = [correct_answer] + wrong_answers
    random.shuffle(all_answers)
    
    # Find the position of the correct answer
    correct_position = all_answers.index(correct_answer)
    
    return templates.TemplateResponse("learn_mode.html", {
        "request": request,
        "user": None,  # No user required
        "flashcard_set": flashcard_set,
        "current_card": current_card,
        "current_question": question,
        "total_questions": total_questions,
        "cards": cards_list,  # Keep all cards for wrong answers
        "answer_options": all_answers,
        "correct_position": correct_position,
        "direction": direction
    })


@app.post("/set/{set_id}/learn", name="learn_mode_post")
async def learn_mode_post(request: Request, set_id: int):
    """Handle Learn mode answer submission - NO AUTH REQUIRED"""
    try:
        form_data = await request.form()
        print(f"Form data received: {dict(form_data)}")
        
        card_id = int(form_data.get("card_id"))
        selected_answer = form_data.get("answer")
        correct_answer = form_data.get("correct_answer")
        direction = form_data.get("direction", "def_to_term")
        current_question = int(form_data.get("current_question", 1))
        
        print(f"Parsed data: card_id={card_id}, selected_answer={selected_answer}, correct_answer={correct_answer}, current_question={current_question}")
        
        # Check if answer is correct
        is_correct = selected_answer == correct_answer
        print(f"Answer is correct: {is_correct}")
        
        # Get total number of questions
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT COUNT(*) as count FROM flashcard WHERE set_id = ?", (set_id,)
        )
        total_questions = cursor.fetchone()["count"]
        print(f"Total questions: {total_questions}")
        
        conn.close()
        
        # Get the flashcard details for result page
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM flashcard WHERE id = ?", (card_id,)
        )
        card = cursor.fetchone()
        
        if not card:
            print(f"Card with id {card_id} not found")
            conn.close()
            return RedirectResponse(
                str(request.url_for("learn_mode", set_id=set_id)),
                status_code=302
            )
        
        cursor.execute(
            "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
        )
        flashcard_set = cursor.fetchone()
        
        if not flashcard_set:
            print(f"Flashcard set with id {set_id} not found")
            conn.close()
            return RedirectResponse(
                str(request.url_for("learn_mode", set_id=set_id)),
                status_code=302
            )
        
        conn.close()
        
        # Determine next question
        next_question = current_question + 1
        is_last_question = next_question > total_questions
        
        print(f"Rendering result page: current_question={current_question}, total_questions={total_questions}, next_question={next_question}")
        
        return templates.TemplateResponse("learn_result.html", {
            "request": request,
            "user": None,  # No user required
            "flashcard_set": flashcard_set,
            "card": card,
            "selected_answer": selected_answer,
            "correct_answer": correct_answer,
            "is_correct": is_correct,
            "current_question": current_question,
            "total_questions": total_questions,
            "next_question": next_question if not is_last_question else None,
            "is_last_question": is_last_question,
            "set_id": set_id,
            "direction": direction
        })
        
    except Exception as e:
        print(f"Error in learn_mode_post: {e}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(
            str(request.url_for("learn_mode", set_id=set_id)),
            status_code=302
        )


# ---------------------------------------------------------------------------
# Route definitions
# ---------------------------------------------------------------------------

@app.get("/", name="index")
def index(request: Request, q: str = ""):
    """Homepage listing public sets and personal sets for logged-in users."""
    user = get_current_user(request)
    conn = get_db_connection()
    # Search public sets by name (case-insensitive)
    if q:
        public_sets = conn.execute(
            "SELECT * FROM flashcard_set WHERE public = 1 AND name LIKE ? ORDER BY name ASC",
            (f"%{q}%",),
        ).fetchall()
    else:
        public_sets = conn.execute(
            "SELECT * FROM flashcard_set WHERE public = 1 ORDER BY name ASC"
        ).fetchall()
    my_sets: List[sqlite3.Row] = []
    collab_sets: List[sqlite3.Row] = []
    if user:
        my_sets = conn.execute(
            "SELECT * FROM flashcard_set WHERE owner_id = ? ORDER BY name ASC",
            (user["id"],),
        ).fetchall()
        # Fetch collaborations via join
        collab_sets = conn.execute(
            """
            SELECT fs.* FROM flashcard_set fs
            JOIN set_collaborator sc ON fs.id = sc.set_id
            WHERE sc.user_id = ?
            ORDER BY fs.name ASC
            """,
            (user["id"],),
        ).fetchall()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "public_sets": public_sets,
            "my_sets": my_sets,
            "collab_sets": collab_sets,
            "query": q,
        },
    )


@app.get("/signup", name="signup_get")
def signup_get(request: Request):
    """Display the registration form."""
    user = get_current_user(request)
    if user:
        return RedirectResponse(str(request.url_for("index")))
    return templates.TemplateResponse("signup.html", {"request": request, "user": None})


@app.post("/signup", name="signup_post")
@rate_limit_signup()
async def signup_post(request: Request):
    """Process the registration form and create a new user with security validation."""
    try:
        # Parse form data manually since python-multipart is unavailable
        body = await request.body()
        data = {k: v[0] for k, v in ({} if not body else parse_qs(body.decode())).items()}
        
        # Validate input using security module
        username = InputValidator.sanitize_username(data.get("username", ""))
        password = data.get("password", "").strip()
        
        if not password:
            return templates.TemplateResponse(
                "signup.html",
                {"request": request, "user": None, "error": "Password is required."},
                status_code=400,
            )
        
        # Validate password strength
        from security import PasswordValidator
        password_validation = PasswordValidator.validate_password_strength(password)
        if not password_validation["valid"]:
            error_msg = "Password requirements not met: " + "; ".join(password_validation["issues"])
            return templates.TemplateResponse(
                "signup.html",
                {"request": request, "user": None, "error": error_msg},
                status_code=400,
            )
        
        conn = get_db_connection()
        existing = conn.execute(
            "SELECT id FROM user WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            return templates.TemplateResponse(
                "signup.html",
                {"request": request, "user": None, "error": "Username is already taken."},
                status_code=400,
            )
        
        # Hash password with secure bcrypt
        password_hash = SecurePasswordManager.hash_password(password)
        
        # Insert user with additional security fields
        conn.execute(
            "INSERT INTO user (username, password_hash, created_at, last_login) VALUES (?, ?, datetime('now'), NULL)",
            (username, password_hash),
        )
        conn.commit()
        
        response = RedirectResponse(str(request.url_for("login_get")), status_code=302)
        return response
        
    except ValueError as e:
        return templates.TemplateResponse(
            "signup.html",
            {"request": request, "user": None, "error": str(e)},
            status_code=400,
        )
    except Exception as e:
        # Log error for security monitoring
        print(f"Signup error: {str(e)}")
        return templates.TemplateResponse(
            "signup.html",
            {"request": request, "user": None, "error": "An error occurred during registration. Please try again."},
            status_code=500,
        )


@app.get("/login", name="login_get")
def login_get(request: Request):
    """Display the login form."""
    user = get_current_user(request)
    if user:
        return RedirectResponse(str(request.url_for("index")))
    return templates.TemplateResponse("login.html", {"request": request, "user": None})


@app.post("/login", name="login_post")
@rate_limit_login()
async def login_post(request: Request):
    """Authenticate a user with comprehensive security measures."""
    try:
        # Get client IP for rate limiting and lockout tracking
        client_ip = request.client.host
        
        # Parse form data
        body = await request.body()
        data = {k: v[0] for k, v in ({} if not body else parse_qs(body.decode())).items()}
        
        # Validate and sanitize input
        username = InputValidator.sanitize_username(data.get("username", ""))
        password = data.get("password", "").strip()
        
        if not password:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "user": None, "error": "Password is required."},
                status_code=400,
            )
        
        # Check for account lockout
        if AccountLockoutManager.is_account_locked(username, client_ip):
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "user": None, "error": "Account temporarily locked due to too many failed attempts. Please try again later."},
                status_code=429,
            )
        
        conn = get_db_connection()
        row = conn.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()
        
        if row and SecurePasswordManager.verify_password(password, row["password_hash"]):
            # Successful login - clear failed attempts
            AccountLockoutManager.clear_failed_attempts(username, client_ip)
            
            # Update last login time
            conn.execute(
                "UPDATE user SET last_login = datetime('now') WHERE id = ?",
                (row["id"],)
            )
            conn.commit()
            
            # Generate secure session
            session_id = generate_secure_token()
            app.state.sessions[session_id] = row["id"]
            
            response = RedirectResponse(str(request.url_for("index")), status_code=302)
            response.set_cookie(
                key="session_id", 
                value=session_id, 
                httponly=True, 
                secure=True,  # HTTPS only in production
                samesite="lax",  # CSRF protection
                max_age=3600  # 1 hour instead of 7 days
            )
            return response
        else:
            # Failed login - record attempt
            AccountLockoutManager.record_failed_attempt(username, client_ip)
            
            # Generic error message to prevent username enumeration
            error_msg = "Invalid username or password."
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "user": None, "error": error_msg},
                status_code=400,
            )
            
    except ValueError as e:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "user": None, "error": str(e)},
            status_code=400,
        )
    except Exception as e:
        # Log error for security monitoring
        print(f"Login error: {str(e)}")
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "user": None, "error": "An error occurred during login. Please try again."},
            status_code=500,
        )


@app.get("/logout", name="logout")
def logout(request: Request):
    """Log the user out by clearing the session."""
    # Remove session mapping and cookie if present
    session_id = request.cookies.get("session_id")
    if session_id and session_id in app.state.sessions:
        del app.state.sessions[session_id]
    response = RedirectResponse(str(request.url_for("index")), status_code=302)
    response.delete_cookie("session_id")
    return response


@app.get("/set/new", name="create_set_get")
def create_set_get(request: Request, user: sqlite3.Row = Depends(require_login)):
    """Display the form to create a new flashcard set."""
    return templates.TemplateResponse(
        "create_set.html", {"request": request, "user": user}
    )


@app.post("/set/new", name="create_set_post")
async def create_set_post(request: Request, user: sqlite3.Row = Depends(require_login)):
    """Handle creation of a new flashcard set."""
    body = await request.body()
    data = {k: v[0] for k, v in ({} if not body else parse_qs(body.decode())).items()}
    name = data.get("name", "").strip()
    public_flag = data.get("public")
    if not name:
        return templates.TemplateResponse(
            "create_set.html",
            {"request": request, "user": user, "error": "Set name is required."},
            status_code=400,
        )
    is_public = 1 if public_flag else 0
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO flashcard_set (name, owner_id, public) VALUES (?, ?, ?)",
        (name, user["id"], is_public),
    )
    conn.commit()
    new_id = cur.lastrowid
    return RedirectResponse(str(request.url_for("view_set", set_id=new_id)), status_code=302)


# Helper function to check editing rights
def can_edit_set(set_id: int, user_id: Optional[int]) -> bool:
    """Return True if the user has editing rights on the set."""
    if user_id is None:
        return False
    conn = get_db_connection()
    # Check ownership
    owned = conn.execute(
        "SELECT 1 FROM flashcard_set WHERE id = ? AND owner_id = ?",
        (set_id, user_id),
    ).fetchone()
    if owned:
        return True
    # Check collaborator
    collab = conn.execute(
        "SELECT 1 FROM set_collaborator WHERE set_id = ? AND user_id = ?",
        (set_id, user_id),
    ).fetchone()
    return bool(collab)


# Helper function to check viewing rights
def can_view_set(set_id: int, user_id: Optional[int], is_public: bool) -> bool:
    """Return True if the user can view the set."""
    if is_public:
        return True  # Public sets can be viewed by anyone
    if user_id is None:
        return False  # Private sets require login
    # For private sets, check if user is owner or collaborator
    return can_edit_set(set_id, user_id)


@app.get("/set/{set_id}", name="view_set")
def view_set(request: Request, set_id: int):
    """Display a flashcard set and allow adding cards if authorized."""
    user = get_current_user(request)
    conn = get_db_connection()
    flashcard_set = conn.execute(
        "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
    ).fetchone()
    if not flashcard_set:
        raise HTTPException(status_code=404)
    # Check visibility: if private and user cannot edit, forbid
    if not flashcard_set["public"]:
        if not can_edit_set(set_id, user["id"] if user else None):
            raise HTTPException(status_code=403)
    # Fetch cards
    cards = conn.execute(
        "SELECT * FROM flashcard WHERE set_id = ? ORDER BY id ASC",
        (set_id,),
    ).fetchall()
    # Fetch collaborators with usernames
    collaborators: List[Tuple[int, str]] = []
    for row in conn.execute(
        """
        SELECT u.id, u.username FROM set_collaborator sc
        JOIN user u ON sc.user_id = u.id
        WHERE sc.set_id = ?
        ORDER BY u.username ASC
        """,
        (set_id,),
    ).fetchall():
        collaborators.append((row[0], row[1]))
    editing = can_edit_set(set_id, user["id"] if user else None)
    return templates.TemplateResponse(
        "set_detail.html",
        {
            "request": request,
            "user": user,
            "flashcard_set": flashcard_set,
            "cards": cards,
            "can_edit": editing,
            "collaborators": collaborators,
        },
    )


@app.post("/set/{set_id}/add_card_ajax", name="add_card_ajax")
async def add_card_ajax(request: Request, set_id: int):
    """Add a new card to a set via AJAX. Returns JSON response."""
    user = get_current_user(request)
    if not can_edit_set(set_id, user["id"] if user else None):
        raise HTTPException(status_code=403)
    
    try:
        # Parse form data properly for AJAX requests
        form_data = await request.form()
        front_text = form_data.get("front", "").strip()
        back_text = form_data.get("back", "").strip()
        
        # Validate and sanitize input
        front = InputValidator.sanitize_flashcard_content(front_text, "Front text")
        back = InputValidator.sanitize_flashcard_content(back_text, "Back text")
        
        conn = get_db_connection()
        
        # Insert card with audit fields
        cursor = conn.execute(
            "INSERT INTO flashcard (set_id, front, back, created_by, updated_by) VALUES (?, ?, ?, ?, ?)",
            (set_id, front, back, user["id"], user["id"]),
        )
        card_id = cursor.lastrowid
        
        # Update set version for optimistic concurrency
        conn.execute(
            "UPDATE flashcard_set SET version = version + 1, updated_at = datetime('now') WHERE id = ?",
            (set_id,)
        )
        
        conn.commit()
        
        # Log security event
        conn.execute(
            "INSERT INTO security_log (user_id, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)",
            (user["id"], "card_created", request.client.host, request.headers.get("user-agent", ""), f"Set ID: {set_id}")
        )
        conn.commit()
        
        return {"success": True, "card_id": card_id, "front": front, "back": back}
        
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        print(f"Card creation error: {str(e)}")
        return {"success": False, "error": "An error occurred while creating the card."}


@app.post("/set/{set_id}", name="add_card")
async def add_card(request: Request, set_id: int):
    """Add a new card to a set with security validation. User must have editing rights."""
    user = get_current_user(request)
    if not can_edit_set(set_id, user["id"] if user else None):
        raise HTTPException(status_code=403)
    
    try:
        body = await request.body()
        data = {k: v[0] for k, v in ({} if not body else parse_qs(body.decode())).items()}
        
        # Validate and sanitize input
        front = InputValidator.sanitize_flashcard_content(data.get("front", ""), "Front text")
        back = InputValidator.sanitize_flashcard_content(data.get("back", ""), "Back text")
        
        conn = get_db_connection()
        
        # Insert card with audit fields
        conn.execute(
            "INSERT INTO flashcard (set_id, front, back, created_by, updated_by) VALUES (?, ?, ?, ?, ?)",
            (set_id, front, back, user["id"], user["id"]),
        )
        
        # Update set version for optimistic concurrency
        conn.execute(
            "UPDATE flashcard_set SET version = version + 1, updated_at = datetime('now') WHERE id = ?",
            (set_id,)
        )
        
        conn.commit()
        
        # Log security event
        conn.execute(
            "INSERT INTO security_log (user_id, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)",
            (user["id"], "card_created", request.client.host, request.headers.get("user-agent", ""), f"Set ID: {set_id}")
        )
        conn.commit()
        
        return RedirectResponse(
            request.url_for("view_set", set_id=set_id), status_code=302
        )
        
    except ValueError as e:
        # Re-render with validation error
        conn = get_db_connection()
        flashcard_set = conn.execute(
            "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
        ).fetchone()
        cards = conn.execute(
            "SELECT * FROM flashcard WHERE set_id = ? ORDER BY id ASC",
            (set_id,),
        ).fetchall()
        collaborators = [
            (row[0], row[1])
            for row in conn.execute(
                """
                SELECT u.id, u.username FROM set_collaborator sc
                JOIN user u ON sc.user_id = u.id
                WHERE sc.set_id = ?
                ORDER BY u.username ASC
                """,
                (set_id,),
            ).fetchall()
        ]
        return templates.TemplateResponse(
            "set_detail.html",
            {
                "request": request,
                "user": user,
                "flashcard_set": flashcard_set,
                "cards": cards,
                "can_edit": True,
                "collaborators": collaborators,
                "error": str(e),
            },
            status_code=400,
        )
    except Exception as e:
        # Log error for security monitoring
        print(f"Card creation error: {str(e)}")
        raise HTTPException(status_code=500, detail="An error occurred while creating the card.")


@app.get("/set/{set_id}/delete_card/{card_id}", name="delete_card_route")
def delete_card_route(request: Request, set_id: int, card_id: int):
    """Delete a card from a set. Only editors can perform this."""
    user = get_current_user(request)
    if not can_edit_set(set_id, user["id"] if user else None):
        raise HTTPException(status_code=403)
    conn = get_db_connection()
    conn.execute(
        "DELETE FROM flashcard WHERE id = ? AND set_id = ?",
        (card_id, set_id),
    )
    conn.commit()
    return RedirectResponse(
        request.url_for("view_set", set_id=set_id), status_code=302
    )


@app.get("/set/{set_id}/delete", name="delete_set_route")
def delete_set_route(request: Request, set_id: int):
    """Delete an entire set. Only editors can perform this."""
    user = get_current_user(request)
    if not can_edit_set(set_id, user["id"] if user else None):
        raise HTTPException(status_code=403)
    conn = get_db_connection()
    conn.execute(
        "DELETE FROM flashcard_set WHERE id = ?", (set_id,)
    )
    conn.commit()
    return RedirectResponse(str(request.url_for("index")), status_code=302)


@app.post("/set/{set_id}/add_collaborator", name="add_collaborator_route")
async def add_collaborator_route(request: Request, set_id: int):
    """Grant editing access to a user by username."""
    user = get_current_user(request)
    if not can_edit_set(set_id, user["id"] if user else None):
        raise HTTPException(status_code=403)
    body = await request.body()
    data = {k: v[0] for k, v in ({} if not body else parse_qs(body.decode())).items()}
    target_username = data.get("username", "").strip().lower()
    if not target_username:
        return RedirectResponse(
            request.url_for("view_set", set_id=set_id), status_code=302
        )
    # Cannot add yourself
    if target_username == user["username"]:
        return RedirectResponse(
            request.url_for("view_set", set_id=set_id), status_code=302
        )
    conn = get_db_connection()
    target_user = conn.execute(
        "SELECT * FROM user WHERE username = ?", (target_username,)
    ).fetchone()
    if not target_user:
        return RedirectResponse(
            request.url_for("view_set", set_id=set_id), status_code=302
        )
    exists = conn.execute(
        "SELECT 1 FROM set_collaborator WHERE set_id = ? AND user_id = ?",
        (set_id, target_user["id"]),
    ).fetchone()
    if exists:
        return RedirectResponse(
            request.url_for("view_set", set_id=set_id), status_code=302
        )
    conn.execute(
        "INSERT INTO set_collaborator (set_id, user_id) VALUES (?, ?)",
        (set_id, target_user["id"]),
    )
    conn.commit()
    return RedirectResponse(
        request.url_for("view_set", set_id=set_id), status_code=302
    )


@app.get("/set/{set_id}/remove_collaborator/{user_id}", name="remove_collaborator_route")
def remove_collaborator_route(request: Request, set_id: int, user_id: int):
    """Remove editing rights from a collaborator."""
    user = get_current_user(request)
    if not can_edit_set(set_id, user["id"] if user else None):
        raise HTTPException(status_code=403)
    conn = get_db_connection()
    conn.execute(
        "DELETE FROM set_collaborator WHERE set_id = ? AND user_id = ?",
        (set_id, user_id),
    )
    conn.commit()
    return RedirectResponse(
        request.url_for("view_set", set_id=set_id), status_code=302
    )


# ---------------------------------------------------------------------------
# Study mode routes
# ---------------------------------------------------------------------------

@app.get("/set/{set_id}/study", name="study_mode_select")
def study_mode_select(request: Request, set_id: int):
    """Display study mode selection page."""
    user = get_current_user(request)
    conn = get_db_connection()
    flashcard_set = conn.execute(
        "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
    ).fetchone()
    if not flashcard_set:
        raise HTTPException(status_code=404)
    
    # Check visibility: if private and user cannot view, forbid
    if not can_view_set(set_id, user["id"] if user else None, flashcard_set["public"]):
        raise HTTPException(status_code=403)
    
    # Check if set has cards
    cards = conn.execute(
        "SELECT * FROM flashcard WHERE set_id = ? ORDER BY id ASC",
        (set_id,),
    ).fetchall()
    
    if not cards:
        return templates.TemplateResponse(
            "study_error.html",
            {
                "request": request,
                "user": user,
                "flashcard_set": flashcard_set,
                "error": "This set has no cards to study."
            },
        )
    
    return templates.TemplateResponse(
        "study_select.html",
        {
            "request": request,
            "user": user,
            "flashcard_set": flashcard_set,
            "card_count": len(cards),
        },
    )


@app.get("/set/{set_id}/study/flashcard", name="flashcard_mode_default")
def flashcard_mode_default(request: Request, set_id: int):
    """Default flashcard mode - redirects to order mode."""
    return RedirectResponse(
        request.url_for("flashcard_mode", set_id=set_id, mode="order"), status_code=302
    )


@app.get("/set/{set_id}/study/flashcard/{mode}", name="flashcard_mode")
def flashcard_mode(request: Request, set_id: int, mode: str):
    """Flashcard study mode - flip through cards."""
    # Validate mode parameter
    if mode not in ["order", "random"]:
        raise HTTPException(status_code=400, detail="Mode must be 'order' or 'random'")
    
    user = get_current_user(request)
    conn = get_db_connection()
    flashcard_set = conn.execute(
        "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
    ).fetchone()
    if not flashcard_set:
        raise HTTPException(status_code=404)
    
    # Check visibility: if private and user cannot view, forbid
    if not can_view_set(set_id, user["id"] if user else None, flashcard_set["public"]):
        raise HTTPException(status_code=403)
    
    # Get cards
    if mode == "random":
        cards = conn.execute(
            "SELECT * FROM flashcard WHERE set_id = ? ORDER BY RANDOM()",
            (set_id,),
        ).fetchall()
    else:
        cards = conn.execute(
            "SELECT * FROM flashcard WHERE set_id = ? ORDER BY id ASC",
            (set_id,),
        ).fetchall()
    
    if not cards:
        raise HTTPException(status_code=404, detail="No cards found")
    
    # Convert Row objects to dictionaries for JSON serialization
    cards_dict = [dict(card) for card in cards]
    
    # Wrap LaTeX content in delimiters for KaTeX rendering
    for card in cards_dict:
        # Check if content looks like LaTeX (contains \frac, \sum, etc.)
        if any(pattern in card['front'] for pattern in ['\\frac', '\\sum', '\\sqrt', '\\int', '\\alpha', '\\beta', '\\gamma', '\\delta', '\\pi', '\\sigma', '\\mu', '\\bar', '\\text']):
            card['front'] = f"${card['front']}$"
        if any(pattern in card['back'] for pattern in ['\\frac', '\\sum', '\\sqrt', '\\int', '\\alpha', '\\beta', '\\gamma', '\\delta', '\\pi', '\\sigma', '\\mu', '\\bar', '\\text']):
            card['back'] = f"${card['back']}$"
    
    # Create a JSON string that preserves LaTeX backslashes
    import json
    cards_json = json.dumps(cards_dict, ensure_ascii=False)
    
    return templates.TemplateResponse(
        "flashcard_mode.html",
        {
            "request": request,
            "user": user,
            "flashcard_set": flashcard_set,
            "cards": cards_dict,
            "cards_json": cards_json,
            "mode": mode,
        },
    )


@app.get("/set/{set_id}/study/test", name="test_mode")
def test_mode(request: Request, set_id: int, num_questions: int = 10):
    """Test mode - multiple choice questions."""
    user = get_current_user(request)
    conn = get_db_connection()
    flashcard_set = conn.execute(
        "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
    ).fetchone()
    if not flashcard_set:
        raise HTTPException(status_code=404)
    
    # Check visibility: if private and user cannot view, forbid
    if not can_view_set(set_id, user["id"] if user else None, flashcard_set["public"]):
        raise HTTPException(status_code=403)
    
    # Get all cards for this set
    cards = conn.execute(
        "SELECT * FROM flashcard WHERE set_id = ? ORDER BY RANDOM()",
        (set_id,),
    ).fetchall()
    
    if len(cards) < 4:
        return templates.TemplateResponse(
            "study_error.html",
            {
                "request": request,
                "user": user,
                "flashcard_set": flashcard_set,
                "error": "Test mode requires at least 4 cards to generate multiple choice questions."
            },
        )
    
    # Validate number of questions
    if num_questions < 1 or num_questions > len(cards):
        return templates.TemplateResponse(
            "study_error.html",
            {
                "request": request,
                "user": user,
                "flashcard_set": flashcard_set,
                "error": f"Number of questions must be between 1 and {len(cards)}."
            },
        )
    
    # Convert Row objects to dictionaries for JSON serialization
    cards_dict = [dict(card) for card in cards]
    
    # Generate test questions with the specified number
    import random
    test_questions = []
    selected_cards = random.sample(cards_dict, num_questions)
    
    for card in selected_cards:
        # Get 3 random wrong answers from other cards
        other_cards = [c for c in cards_dict if c["id"] != card["id"]]
        wrong_answers = random.sample(other_cards, min(3, len(other_cards)))
        wrong_answer_texts = [c["back"] for c in wrong_answers]
        
        # Create answer options
        correct_answer = card["back"]
        all_answers = [correct_answer] + wrong_answer_texts
        random.shuffle(all_answers)
        
        test_questions.append({
            "id": card["id"],
            "question": card["front"],
            "correct_answer": correct_answer,
            "answers": all_answers,
            "correct_index": all_answers.index(correct_answer)
        })
    
    return templates.TemplateResponse(
        "test_mode.html",
        {
            "request": request,
            "user": user,
            "flashcard_set": flashcard_set,
            "questions": test_questions,
        },
    )


@app.post("/set/{set_id}/study/test/submit", name="submit_test")
async def submit_test(request: Request, set_id: int):
    """Submit test answers and show results."""
    user = get_current_user(request)
    conn = get_db_connection()
    flashcard_set = conn.execute(
        "SELECT * FROM flashcard_set WHERE id = ?", (set_id,)
    ).fetchone()
    if not flashcard_set:
        raise HTTPException(status_code=404)
    
    # Check visibility: if private and user cannot view, forbid
    if not can_view_set(set_id, user["id"] if user else None, flashcard_set["public"]):
        raise HTTPException(status_code=403)
    
    # Parse form data
    body = await request.body()
    data = {k: v[0] for k, v in ({} if not body else parse_qs(body.decode())).items()}
    
    # Get the number of questions from form data
    num_questions = int(data.get("num_questions", 10))
    
    # Get the original questions to check answers
    cards = conn.execute(
        "SELECT * FROM flashcard WHERE set_id = ? ORDER BY id ASC",
        (set_id,),
    ).fetchall()
    
    # Convert Row objects to dictionaries for JSON serialization
    cards_dict = [dict(card) for card in cards]
    
    # Reconstruct questions (in a real app, you'd store this in session)
    import random
    test_questions = []
    # Use the actual number of questions from the form
    selected_cards = random.sample(cards_dict, min(num_questions, len(cards_dict)))
    
    for card in selected_cards:
        other_cards = [c for c in cards_dict if c["id"] != card["id"]]
        wrong_answers = random.sample(other_cards, min(3, len(other_cards)))
        wrong_answer_texts = [c["back"] for c in wrong_answers]
        
        correct_answer = card["back"]
        all_answers = [correct_answer] + wrong_answer_texts
        random.shuffle(all_answers)
        
        test_questions.append({
            "id": card["id"],
            "question": card["front"],
            "correct_answer": correct_answer,
            "answers": all_answers,
            "correct_index": all_answers.index(correct_answer)
        })
    
    # Check answers
    score = 0
    results = []
    for i, question in enumerate(test_questions):
        user_answer = data.get(f"question_{i}", "")
        is_correct = user_answer == str(question["correct_index"])
        if is_correct:
            score += 1
        
        results.append({
            "question": question["question"],
            "user_answer": question["answers"][int(user_answer)] if user_answer.isdigit() and int(user_answer) < len(question["answers"]) else "No answer",
            "correct_answer": question["correct_answer"],
            "is_correct": is_correct
        })
    
    percentage = (score / len(test_questions)) * 100 if test_questions else 0
    
    return templates.TemplateResponse(
        "test_results.html",
        {
            "request": request,
            "user": user,
            "flashcard_set": flashcard_set,
            "results": results,
            "score": score,
            "total": len(test_questions),
            "percentage": percentage,
        },
    )


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.get("/admin", name="admin_dashboard")
def admin_dashboard(request: Request):
    """Admin dashboard with system overview."""
    # Check admin access
    admin_check = check_admin_access(request)
    if isinstance(admin_check, RedirectResponse):
        return admin_check
    admin_user = admin_check
    
    try:
        conn = get_db_connection()
        
        # Get basic statistics with error handling
        try:
            total_users = conn.execute("SELECT COUNT(*) FROM user").fetchone()[0]
        except:
            total_users = 0
            
        try:
            active_users = conn.execute("SELECT COUNT(*) FROM user WHERE is_active = 1").fetchone()[0]
        except:
            active_users = 0
            
        try:
            total_sets = conn.execute("SELECT COUNT(*) FROM flashcard_set").fetchone()[0]
        except:
            total_sets = 0
            
        try:
            public_sets = conn.execute("SELECT COUNT(*) FROM flashcard_set WHERE public = 1").fetchone()[0]
        except:
            public_sets = 0
            
        try:
            total_cards = conn.execute("SELECT COUNT(*) FROM flashcard").fetchone()[0]
        except:
            total_cards = 0
        
        # Recent security events
        try:
            recent_security_events = conn.execute(
                "SELECT * FROM security_log ORDER BY created_at DESC LIMIT 10"
            ).fetchall()
        except:
            recent_security_events = []
        
        # Recent user registrations
        try:
            recent_users = conn.execute(
                "SELECT username, created_at, last_login FROM user ORDER BY created_at DESC LIMIT 10"
            ).fetchall()
        except:
            recent_users = []
        
        return templates.TemplateResponse(
            "admin/dashboard_simple.html",
            {
                "request": request,
                "user": admin_user,
                "stats": {
                    "total_users": total_users,
                    "active_users": active_users,
                    "total_sets": total_sets,
                    "public_sets": public_sets,
                    "total_cards": total_cards,
                },
                "recent_security_events": recent_security_events,
                "recent_users": recent_users,
            },
        )
    except Exception as e:
        print(f"Admin dashboard error: {e}")
        raise HTTPException(status_code=500, detail=f"Admin dashboard error: {str(e)}")


@app.get("/admin/users", name="admin_users")
def admin_users(request: Request):
    """User management page."""
    # Check admin access
    admin_check = check_admin_access(request)
    if isinstance(admin_check, RedirectResponse):
        return admin_check
    admin_user = admin_check
    
    conn = get_db_connection()
    users = conn.execute(
        "SELECT id, username, email, created_at, last_login, failed_login_attempts, account_locked_until, is_admin, is_active FROM user ORDER BY created_at DESC"
    ).fetchall()
    
    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "user": admin_user,
            "users": users,
        },
    )


@app.get("/admin/security", name="admin_security")
def admin_security(request: Request):
    """Security logs and monitoring page."""
    # Check admin access
    admin_check = check_admin_access(request)
    if isinstance(admin_check, RedirectResponse):
        return admin_check
    admin_user = admin_check
    
    conn = get_db_connection()
    
    # Get security events with pagination
    page = int(request.query_params.get("page", 1))
    per_page = 50
    offset = (page - 1) * per_page
    
    security_events = conn.execute(
        "SELECT sl.*, u.username FROM security_log sl LEFT JOIN user u ON sl.user_id = u.id ORDER BY sl.created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset)
    ).fetchall()
    
    total_events = conn.execute("SELECT COUNT(*) FROM security_log").fetchone()[0]
    total_pages = (total_events + per_page - 1) // per_page
    
    # Get event type statistics
    event_stats = conn.execute(
        "SELECT event_type, COUNT(*) as count FROM security_log GROUP BY event_type ORDER BY count DESC"
    ).fetchall()
    
    return templates.TemplateResponse(
        "admin/security.html",
        {
            "request": request,
            "user": admin_user,
            "security_events": security_events,
            "event_stats": event_stats,
            "pagination": {
                "page": page,
                "total_pages": total_pages,
                "has_prev": page > 1,
                "has_next": page < total_pages,
                "prev_page": page - 1 if page > 1 else None,
                "next_page": page + 1 if page < total_pages else None,
            },
        },
    )


@app.post("/admin/users/{user_id}/toggle_admin", name="toggle_admin")
def toggle_admin(request: Request, user_id: int):
    """Toggle admin status for a user."""
    # Check admin access
    admin_check = check_admin_access(request)
    if isinstance(admin_check, RedirectResponse):
        return admin_check
    admin_user = admin_check
    
    conn = get_db_connection()
    
    # Prevent self-demotion
    if user_id == admin_user["id"]:
        return RedirectResponse(
            request.url_for("admin_users"), 
            status_code=302
        )
    
    # Toggle admin status
    conn.execute(
        "UPDATE user SET is_admin = NOT is_admin WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    
    # Log the action
    conn.execute(
        "INSERT INTO security_log (user_id, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)",
        (admin_user["id"], "admin_toggle", request.client.host, request.headers.get("user-agent", ""), f"Toggled admin for user ID: {user_id}")
    )
    conn.commit()
    
    return RedirectResponse(
        request.url_for("admin_users"), 
        status_code=302
    )


@app.post("/admin/users/{user_id}/toggle_active", name="toggle_active")
def toggle_active(request: Request, user_id: int):
    """Toggle active status for a user."""
    # Check admin access
    admin_check = check_admin_access(request)
    if isinstance(admin_check, RedirectResponse):
        return admin_check
    admin_user = admin_check
    
    conn = get_db_connection()
    
    # Prevent self-deactivation
    if user_id == admin_user["id"]:
        return RedirectResponse(
            request.url_for("admin_users"), 
            status_code=302
        )
    
    # Toggle active status
    conn.execute(
        "UPDATE user SET is_active = NOT is_active WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    
    # Log the action
    conn.execute(
        "INSERT INTO security_log (user_id, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)",
        (admin_user["id"], "user_toggle", request.client.host, request.headers.get("user-agent", ""), f"Toggled active status for user ID: {user_id}")
    )
    conn.commit()
    
    return RedirectResponse(
        request.url_for("admin_users"), 
        status_code=302
    )


@app.post("/admin/users/{user_id}/unlock", name="unlock_user")
def unlock_user(request: Request, user_id: int):
    """Unlock a locked user account."""
    # Check admin access
    admin_check = check_admin_access(request)
    if isinstance(admin_check, RedirectResponse):
        return admin_check
    admin_user = admin_check
    
    conn = get_db_connection()
    
    # Clear lockout
    conn.execute(
        "UPDATE user SET account_locked_until = NULL, failed_login_attempts = 0 WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    
    # Log the action
    conn.execute(
        "INSERT INTO security_log (user_id, event_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)",
        (admin_user["id"], "user_unlock", request.client.host, request.headers.get("user-agent", ""), f"Unlocked user ID: {user_id}")
    )
    conn.commit()
    
    return RedirectResponse(
        request.url_for("admin_users"), 
        status_code=302
    )


# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)