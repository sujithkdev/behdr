# server/password_policy.py — Password Policy Enforcement
"""
Password policy with complexity requirements and forced change on first login.

Features:
  • Minimum length (default: 12 characters)
  • Complexity requirements (uppercase, lowercase, digit, special char)
  • Force password change on first login
  • Password history (prevent reuse)
  • Configurable policy

Integration:
  Used by auth.py for password validation
"""

import re
import hashlib
import json
import os
from datetime import datetime

from server.config import DATA_DIR

# ── Configuration ─────────────────────────────────────────────────────────────
MIN_PASSWORD_LENGTH = 12
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SPECIAL_CHAR = True
PASSWORD_HISTORY_SIZE = 3         # Prevent reusing last 3 passwords
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# ── Password history storage ──────────────────────────────────────────────────
PASSWORD_HISTORY_FILE = os.path.join(DATA_DIR, "password_history.json")


def _load_password_history() -> dict:
    """Load password history from disk."""
    if not os.path.exists(PASSWORD_HISTORY_FILE):
        return {}
    
    try:
        with open(PASSWORD_HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_password_history(history: dict):
    """Save password history to disk."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(PASSWORD_HISTORY_FILE, "w") as f:
            json.dump(history, f)
    except Exception as e:
        print(f"[PASSWORD] Failed to save history: {e}")


def _hash_password(password: str) -> str:
    """Hash password for history comparison."""
    return hashlib.sha256(password.encode()).hexdigest()


def validate_password_strength(password: str) -> tuple:
    """
    Validate password against policy.
    
    Returns:
        (valid: bool, error_message: str)
    """
    if not password:
        return (False, "Password cannot be empty")
    
    # Length check
    if len(password) < MIN_PASSWORD_LENGTH:
        return (False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")
    
    # Complexity checks
    errors = []
    
    if REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        errors.append("at least one uppercase letter")
    
    if REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        errors.append("at least one lowercase letter")
    
    if REQUIRE_DIGIT and not re.search(r'[0-9]', password):
        errors.append("at least one digit")
    
    if REQUIRE_SPECIAL_CHAR and not re.search(f'[{re.escape(SPECIAL_CHARS)}]', password):
        errors.append(f"at least one special character ({SPECIAL_CHARS[:10]}...)")
    
    if errors:
        return (False, f"Password must contain {', '.join(errors)}")
    
    return (True, "")


def check_password_history(username: str, new_password: str) -> tuple:
    """
    Check if password was used recently.
    
    Returns:
        (allowed: bool, error_message: str)
    """
    if PASSWORD_HISTORY_SIZE == 0:
        return (True, "")
    
    history = _load_password_history()
    user_history = history.get(username, [])
    
    new_hash = _hash_password(new_password)
    
    # Check against recent passwords
    for old_hash in user_history[-PASSWORD_HISTORY_SIZE:]:
        if new_hash == old_hash:
            return (False, f"Cannot reuse any of your last {PASSWORD_HISTORY_SIZE} passwords")
    
    return (True, "")


def record_password_change(username: str, new_password: str):
    """Record password change in history."""
    if PASSWORD_HISTORY_SIZE == 0:
        return
    
    history = _load_password_history()
    
    if username not in history:
        history[username] = []
    
    # Add new password hash
    new_hash = _hash_password(new_password)
    history[username].append(new_hash)
    
    # Keep only last N passwords
    if len(history[username]) > PASSWORD_HISTORY_SIZE:
        history[username] = history[username][-PASSWORD_HISTORY_SIZE:]
    
    _save_password_history(history)


def is_default_password(username: str) -> bool:
    """
    Check if user is still using the default password.
    
    Default passwords:
      - admin: "change-me-now"
      - others: username (e.g., analyst: "analyst")
    """
    if username == "admin":
        # Check if admin is using default password
        from server.auth import _users, _hash_password as auth_hash
        admin_hash = _users.get("admin", {}).get("password")
        default_hash = auth_hash("change-me-now")
        return admin_hash == default_hash
    else:
        # Check if user password equals username
        from server.auth import _users, _hash_password as auth_hash
        user_hash = _users.get(username, {}).get("password")
        username_hash = auth_hash(username)
        return user_hash == username_hash


def get_password_policy() -> dict:
    """Get current password policy settings."""
    return {
        "min_length": MIN_PASSWORD_LENGTH,
        "require_uppercase": REQUIRE_UPPERCASE,
        "require_lowercase": REQUIRE_LOWERCASE,
        "require_digit": REQUIRE_DIGIT,
        "require_special_char": REQUIRE_SPECIAL_CHAR,
        "special_chars": SPECIAL_CHARS,
        "password_history_size": PASSWORD_HISTORY_SIZE
    }


def validate_and_check_password(username: str, new_password: str) -> tuple:
    """
    Validate password strength and check history.
    
    Returns:
        (valid: bool, error_message: str)
    """
    # Check strength
    valid, error = validate_password_strength(new_password)
    if not valid:
        return (False, error)
    
    # Check history
    allowed, error = check_password_history(username, new_password)
    if not allowed:
        return (False, error)
    
    return (True, "")
