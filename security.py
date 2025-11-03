"""
Production-grade security module for the Quizzy flashcard application.

This module implements comprehensive security features including:
- Secure password hashing with bcrypt
- Input validation with Pydantic
- Rate limiting and account lockout
- Session security
- CSRF protection
"""

import os
import re
import time
import secrets
import json
from typing import Optional, Dict, Any
from functools import wraps

import bcrypt
from pydantic import BaseModel, validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse
from passlib.context import CryptContext

# Fix bcrypt version detection issue
try:
    import bcrypt
    if not hasattr(bcrypt, '__about__'):
        # Create a mock __about__ object for version detection
        class MockAbout:
            __version__ = "4.1.2"
        bcrypt.__about__ = MockAbout()
except ImportError:
    pass

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
PASSWORD_RESET_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__default_rounds=12)

# Rate limiter (in-memory fallback)
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

# Account lockout tracking
FAILED_LOGIN_ATTEMPTS = {}
LOCKOUT_DURATION = 15 * 60  # 15 minutes
MAX_FAILED_ATTEMPTS = 5


class PasswordValidator:
    """Comprehensive password validation with security best practices."""
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """
        Validate password strength and return detailed feedback.
        
        Returns:
            Dict with 'valid' boolean and 'issues' list
        """
        issues = []
        
        # Length check
        if len(password) < 8:
            issues.append("Password must be at least 8 characters long")
        elif len(password) > 128:
            issues.append("Password must be no more than 128 characters long")
        
        # Character variety checks
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")
        
        # Common password patterns
        common_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                issues.append("Password contains common patterns that are easy to guess")
                break
        
        # Check against common passwords (simplified check)
        common_passwords = [
            "password", "123456", "123456789", "qwerty", "abc123",
            "password123", "admin", "letmein", "welcome", "monkey"
        ]
        
        if password.lower() in common_passwords:
            issues.append("Password is too common and easily guessable")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "strength": PasswordValidator._calculate_strength(password)
        }
    
    @staticmethod
    def _calculate_strength(password: str) -> str:
        """Calculate password strength score."""
        score = 0
        
        # Length scoring
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        
        # Character variety scoring
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        
        # Determine strength level
        if score <= 3:
            return "weak"
        elif score <= 5:
            return "medium"
        elif score <= 7:
            return "strong"
        else:
            return "very_strong"


class SecurePasswordManager:
    """Production-grade password management with bcrypt."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password using bcrypt with automatic salt generation.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        # Hash with bcrypt (automatically generates salt)
        # Note: Password validation should be done at the API level, not here
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Plain text password to verify
            hashed_password: Stored hash to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def needs_update(hashed_password: str) -> bool:
        """
        Check if password hash needs updating (e.g., algorithm upgrade).
        
        Args:
            hashed_password: Current password hash
            
        Returns:
            True if hash should be updated
        """
        return pwd_context.needs_update(hashed_password)


class AccountLockoutManager:
    """Manage account lockout after failed login attempts."""
    
    @staticmethod
    def record_failed_attempt(username: str, ip_address: str) -> None:
        """Record a failed login attempt."""
        current_time = time.time()
        key = f"failed_login:{username}:{ip_address}"
        
        # In-memory fallback
        record = FAILED_LOGIN_ATTEMPTS.get(key)
        if record and record.get("expires_at", 0) > current_time:
            record["count"] += 1
        else:
            record = {"count": 1, "expires_at": current_time + LOCKOUT_DURATION}
        FAILED_LOGIN_ATTEMPTS[key] = record
    
    @staticmethod
    def is_account_locked(username: str, ip_address: str) -> bool:
        """Check if account is locked due to failed attempts."""
        key = f"failed_login:{username}:{ip_address}"
        current_time = time.time()
        record = FAILED_LOGIN_ATTEMPTS.get(key)
        if not record:
            return False
        if record.get("expires_at", 0) <= current_time:
            # Expired, cleanup
            FAILED_LOGIN_ATTEMPTS.pop(key, None)
            return False
        return record.get("count", 0) >= MAX_FAILED_ATTEMPTS
    
    @staticmethod
    def clear_failed_attempts(username: str, ip_address: str) -> None:
        """Clear failed attempts after successful login."""
        key = f"failed_login:{username}:{ip_address}"
        FAILED_LOGIN_ATTEMPTS.pop(key, None)


class InputValidator:
    """Comprehensive input validation with security focus."""
    
    @staticmethod
    def sanitize_username(username: str) -> str:
        """Sanitize and validate username."""
        if not username:
            raise ValueError("Username is required")
        
        username = username.strip().lower()
        
        # Length validation
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if len(username) > 20:
            raise ValueError("Username must be no more than 20 characters long")
        
        # Character validation (alphanumeric, underscore, hyphen only)
        if not re.match(r'^[a-z0-9_-]+$', username):
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        
        # Reserved usernames
        reserved = ["admin", "root", "api", "www", "mail", "ftp", "support", "help"]
        if username in reserved:
            raise ValueError("This username is reserved and cannot be used")
        
        return username
    
    @staticmethod
    def sanitize_flashcard_content(content: str, field_name: str) -> str:
        """Sanitize flashcard content with length limits."""
        if not content:
            raise ValueError(f"{field_name} is required")
        
        content = content.strip()
        
        # Length validation
        if len(content) > 8192:  # 8KB limit
            raise ValueError(f"{field_name} must be no more than 8192 characters")
        
        # Basic XSS protection (remove script tags)
        content = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', content, flags=re.IGNORECASE)
        
        return content
    
    @staticmethod
    def sanitize_set_name(name: str) -> str:
        """Sanitize flashcard set name."""
        if not name:
            raise ValueError("Set name is required")
        
        name = name.strip()
        
        # Length validation
        if len(name) < 1:
            raise ValueError("Set name cannot be empty")
        if len(name) > 120:
            raise ValueError("Set name must be no more than 120 characters")
        
        return name


class CSRFProtection:
    """CSRF token generation and validation."""
    
    @staticmethod
    def generate_token() -> str:
        """Generate a secure CSRF token."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_token(token: str, session_token: str) -> bool:
        """Validate CSRF token against session token."""
        if not token or not session_token:
            return False
        return secrets.compare_digest(token, session_token)


class SecurityHeaders:
    """Security headers middleware for FastAPI."""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get comprehensive security headers."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; connect-src 'self';",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin"
        }


# Simplified models for basic validation
class UserRegistration(BaseModel):
    """User registration model."""
    username: str
    password: str


class UserLogin(BaseModel):
    """User login model."""
    username: str
    password: str


# Rate limiting decorators
def rate_limit_login():
    """Rate limit for login attempts."""
    return limiter.limit("5/minute")

def rate_limit_signup():
    """Rate limit for signup attempts."""
    return limiter.limit("3/minute")

def rate_limit_general():
    """General rate limit for API endpoints."""
    return limiter.limit("60/minute")


# Security middleware
def add_security_headers_middleware(app):
    """Add security headers middleware to FastAPI app."""
    
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers
        for header, value in SecurityHeaders.get_security_headers().items():
            response.headers[header] = value
        
        return response


# Error handlers
def setup_security_error_handlers(app):
    """Setup security-related error handlers."""
    
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "message": "Too many requests. Please try again later.",
                "retry_after": getattr(exc, 'retry_after', 60)
            }
        )
    
    @app.exception_handler(ValueError)
    async def validation_error_handler(request: Request, exc: ValueError):
        return JSONResponse(
            status_code=400,
            content={
                "error": "Validation error",
                "message": str(exc)
            }
        )


# Utility functions
def generate_secure_token() -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(32)


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for logging purposes."""
    return hashlib.sha256(data.encode()).hexdigest()[:16]


# Export main classes and functions
__all__ = [
    'SecurePasswordManager',
    'PasswordValidator', 
    'AccountLockoutManager',
    'InputValidator',
    'CSRFProtection',
    'SecurityHeaders',
    'UserRegistration',
    'UserLogin',
    'FlashcardCreate',
    'SetCreate',
    'rate_limit_login',
    'rate_limit_signup', 
    'rate_limit_general',
    'add_security_headers_middleware',
    'setup_security_error_handlers',
    'generate_secure_token',
    'hash_sensitive_data'
]
