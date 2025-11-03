#!/usr/bin/env python3
"""
Database Migration Script
Handles migration from old schema to new schema with security updates
"""

import sqlite3
import os
from typing import List, Tuple

# Database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "flashcards.db")

def get_db_connection() -> sqlite3.Connection:
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def check_column_exists(cursor: sqlite3.Cursor, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def add_column_if_not_exists(cursor: sqlite3.Cursor, table_name: str, column_name: str, column_definition: str):
    """Add a column to a table if it doesn't exist"""
    if not check_column_exists(cursor, table_name, column_name):
        print(f"Adding column {column_name} to table {table_name}")
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")
    else:
        print(f"Column {column_name} already exists in table {table_name}")

def migrate_user_table(cursor: sqlite3.Cursor):
    """Migrate user table to add new security columns"""
    print("Migrating user table...")
    
    # Add new columns if they don't exist (without CURRENT_TIMESTAMP defaults)
    add_column_if_not_exists(cursor, "user", "created_at", "DATETIME")
    add_column_if_not_exists(cursor, "user", "last_login", "DATETIME")
    add_column_if_not_exists(cursor, "user", "failed_login_attempts", "INTEGER DEFAULT 0")
    add_column_if_not_exists(cursor, "user", "account_locked_until", "DATETIME")
    add_column_if_not_exists(cursor, "user", "email", "TEXT")
    add_column_if_not_exists(cursor, "user", "email_verified", "BOOLEAN DEFAULT 0")
    add_column_if_not_exists(cursor, "user", "is_admin", "BOOLEAN DEFAULT 0")
    add_column_if_not_exists(cursor, "user", "is_active", "BOOLEAN DEFAULT 1")

def migrate_flashcard_set_table(cursor: sqlite3.Cursor):
    """Migrate flashcard_set table to add new columns"""
    print("Migrating flashcard_set table...")
    
    # Add new columns if they don't exist (without CURRENT_TIMESTAMP defaults)
    add_column_if_not_exists(cursor, "flashcard_set", "created_at", "DATETIME")
    add_column_if_not_exists(cursor, "flashcard_set", "updated_at", "DATETIME")
    add_column_if_not_exists(cursor, "flashcard_set", "version", "INTEGER DEFAULT 1")

def migrate_flashcard_table(cursor: sqlite3.Cursor):
    """Migrate flashcard table to add new columns"""
    print("Migrating flashcard table...")
    
    # Add new columns if they don't exist (without CURRENT_TIMESTAMP defaults)
    add_column_if_not_exists(cursor, "flashcard", "created_at", "DATETIME")
    add_column_if_not_exists(cursor, "flashcard", "updated_at", "DATETIME")
    add_column_if_not_exists(cursor, "flashcard", "version", "INTEGER DEFAULT 1")
    add_column_if_not_exists(cursor, "flashcard", "created_by", "INTEGER")
    add_column_if_not_exists(cursor, "flashcard", "updated_by", "INTEGER")

def migrate_set_collaborator_table(cursor: sqlite3.Cursor):
    """Migrate set_collaborator table to add new columns"""
    print("Migrating set_collaborator table...")
    
    # Add new columns if they don't exist (without CURRENT_TIMESTAMP defaults)
    add_column_if_not_exists(cursor, "set_collaborator", "role", "TEXT DEFAULT 'editor'")
    add_column_if_not_exists(cursor, "set_collaborator", "created_at", "DATETIME")

def create_security_log_table(cursor: sqlite3.Cursor):
    """Create security_log table if it doesn't exist"""
    print("Creating security_log table...")
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            event_description TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user(id)
        )
    """)

def create_indexes(cursor: sqlite3.Cursor):
    """Create indexes for performance"""
    print("Creating indexes...")
    
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_user_username ON user(username)",
        "CREATE INDEX IF NOT EXISTS idx_user_email ON user(email)",
        "CREATE INDEX IF NOT EXISTS idx_flashcard_set_owner ON flashcard_set(owner_id)",
        "CREATE INDEX IF NOT EXISTS idx_flashcard_set_id ON flashcard(set_id)",
        "CREATE INDEX IF NOT EXISTS idx_set_collaborator_set_id ON set_collaborator(set_id)",
        "CREATE INDEX IF NOT EXISTS idx_security_log_user_id ON security_log(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_security_log_timestamp ON security_log(timestamp)"
    ]
    
    for index_sql in indexes:
        try:
            cursor.execute(index_sql)
        except sqlite3.Error as e:
            print(f"Warning: Could not create index: {e}")

def backup_database():
    """Create a backup of the current database"""
    if os.path.exists(DATABASE_PATH):
        backup_path = DATABASE_PATH + ".backup"
        print(f"Creating backup: {backup_path}")
        
        # Copy the database file
        import shutil
        shutil.copy2(DATABASE_PATH, backup_path)
        print("Backup created successfully!")
        return backup_path
    return None

def main():
    """Main migration function"""
    print("🔄 Starting Database Migration")
    print("=" * 50)
    
    # Create backup
    backup_path = backup_database()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if database exists and has data
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        if cursor.fetchone():
            print("✅ Existing database found, starting migration...")
            
            # Migrate existing tables
            migrate_user_table(cursor)
            migrate_flashcard_set_table(cursor)
            migrate_flashcard_table(cursor)
            migrate_set_collaborator_table(cursor)
            
        else:
            print("📝 No existing database found, creating new schema...")
        
        # Create new tables
        create_security_log_table(cursor)
        
        # Create indexes
        create_indexes(cursor)
        
        # Commit changes
        conn.commit()
        
        print("\n✅ Database migration completed successfully!")
        print(f"📁 Backup created at: {backup_path}")
        
        # Verify migration
        cursor.execute("PRAGMA table_info(user)")
        user_columns = [row[1] for row in cursor.fetchall()]
        print(f"📊 User table columns: {user_columns}")
        
        cursor.execute("SELECT COUNT(*) FROM user")
        user_count = cursor.fetchone()[0]
        print(f"👥 Users in database: {user_count}")
        
        cursor.execute("SELECT COUNT(*) FROM flashcard_set")
        set_count = cursor.fetchone()[0]
        print(f"📚 Flashcard sets: {set_count}")
        
        cursor.execute("SELECT COUNT(*) FROM flashcard")
        card_count = cursor.fetchone()[0]
        print(f"🃏 Flashcards: {card_count}")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        if backup_path and os.path.exists(backup_path):
            print(f"🔄 Restoring from backup: {backup_path}")
            import shutil
            shutil.copy2(backup_path, DATABASE_PATH)
        raise
    
    finally:
        conn.close()

if __name__ == "__main__":
    main()
