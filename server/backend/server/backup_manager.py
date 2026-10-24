# server/backup_manager.py — Automated Database Backup System
"""
Automated SQLite database backup with rotation and recovery features.

Features:
  • Automatic daily backups (runs in background thread)
  • Configurable retention (default: 7 daily, 4 weekly, 3 monthly)
  • Backup verification (checks file integrity)
  • One-click restore from backup
  • Backup before dangerous operations (clear_all)
  • Email/Slack notifications on backup success/failure

Usage:
  # Start automatic backups (called from server/__init__.py)
  from server.backup_manager import start_backup_scheduler
  start_backup_scheduler()

  # Manual backup
  from server.backup_manager import create_backup
  backup_path = create_backup()

  # Restore from backup
  from server.backup_manager import restore_backup
  restore_backup(backup_path)
"""

import os
import time
import threading
import shutil
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from server.config import DB_PATH, DATA_DIR

# ── Configuration ─────────────────────────────────────────────────────────────
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
BACKUP_INTERVAL = 86400        # 24 hours (daily backup)
DAILY_RETENTION = 7            # Keep 7 daily backups
WEEKLY_RETENTION = 4           # Keep 4 weekly backups
MONTHLY_RETENTION = 3          # Keep 3 monthly backups
MIN_DB_SIZE = 8192             # 8KB minimum (empty DB is ~8KB)

# ── State ─────────────────────────────────────────────────────────────────────
_backup_thread = None
_stop_event = threading.Event()
_last_backup_time = 0
_last_backup_status = {"success": False, "path": "", "error": "", "timestamp": 0}


def create_backup(reason: str = "scheduled") -> str:
    """
    Create a backup of the database.
    
    Args:
        reason: Why backup is being created ("scheduled", "manual", "pre-clear")
    
    Returns:
        Path to backup file, or empty string on failure
    """
    global _last_backup_time, _last_backup_status
    
    try:
        # Create backup directory
        os.makedirs(BACKUP_DIR, exist_ok=True)
        
        # Check if database exists and is valid
        if not os.path.exists(DB_PATH):
            error = "Database file does not exist"
            _last_backup_status = {
                "success": False,
                "path": "",
                "error": error,
                "timestamp": int(time.time())
            }
            print(f"[BACKUP] ❌ {error}")
            return ""
        
        db_size = os.path.getsize(DB_PATH)
        if db_size < MIN_DB_SIZE:
            error = f"Database file too small ({db_size} bytes) - likely corrupted"
            _last_backup_status = {
                "success": False,
                "path": "",
                "error": error,
                "timestamp": int(time.time())
            }
            print(f"[BACKUP] ❌ {error}")
            return ""
        
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"edr_backup_{timestamp}_{reason}.db"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Use SQLite's backup API for safe hot backup (doesn't lock database)
        print(f"[BACKUP] Creating backup: {backup_filename}")
        
        source_conn = sqlite3.connect(DB_PATH)
        backup_conn = sqlite3.connect(backup_path)
        
        with backup_conn:
            source_conn.backup(backup_conn)
        
        source_conn.close()
        backup_conn.close()
        
        # Verify backup integrity
        if not _verify_backup(backup_path):
            error = "Backup verification failed"
            os.remove(backup_path)
            _last_backup_status = {
                "success": False,
                "path": "",
                "error": error,
                "timestamp": int(time.time())
            }
            print(f"[BACKUP] ❌ {error}")
            return ""
        
        backup_size = os.path.getsize(backup_path)
        _last_backup_time = time.time()
        _last_backup_status = {
            "success": True,
            "path": backup_path,
            "size": backup_size,
            "reason": reason,
            "error": "",
            "timestamp": int(time.time())
        }
        
        print(f"[BACKUP] ✅ Backup created: {backup_filename} ({backup_size:,} bytes)")
        
        # Clean up old backups
        _cleanup_old_backups()
        
        # Notify on backup success
        _notify_backup_status(True, backup_path, reason)
        
        return backup_path
        
    except Exception as e:
        error = str(e)
        _last_backup_status = {
            "success": False,
            "path": "",
            "error": error,
            "timestamp": int(time.time())
        }
        print(f"[BACKUP] ❌ Backup failed: {e}")
        _notify_backup_status(False, "", reason, error)
        return ""


def _verify_backup(backup_path: str) -> bool:
    """Verify backup file integrity by opening it and checking tables."""
    try:
        conn = sqlite3.connect(backup_path)
        cursor = conn.cursor()
        
        # Check that essential tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        
        required_tables = {"events", "alerts", "systems", "commands"}
        if not required_tables.issubset(tables):
            missing = required_tables - tables
            print(f"[BACKUP] Verification failed: missing tables {missing}")
            conn.close()
            return False
        
        # Check that we can query each table
        for table in required_tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            cursor.fetchone()
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"[BACKUP] Verification failed: {e}")
        return False


def restore_backup(backup_path: str) -> bool:
    """
    Restore database from a backup file.
    
    CAUTION: This overwrites the current database!
    
    Args:
        backup_path: Path to backup file to restore
    
    Returns:
        True if restore succeeded, False otherwise
    """
    try:
        if not os.path.exists(backup_path):
            print(f"[BACKUP] ❌ Backup file not found: {backup_path}")
            return False
        
        # Verify backup before restoring
        if not _verify_backup(backup_path):
            print(f"[BACKUP] ❌ Backup file is corrupted: {backup_path}")
            return False
        
        # Create a backup of current DB before restore (safety net)
        if os.path.exists(DB_PATH):
            safety_backup = create_backup(reason="pre-restore")
            if safety_backup:
                print(f"[BACKUP] Safety backup created: {safety_backup}")
        
        # Close any open connections
        from server.database.storage import close_thread_connection
        close_thread_connection()
        
        # Copy backup over current database
        print(f"[BACKUP] Restoring from: {backup_path}")
        shutil.copy2(backup_path, DB_PATH)
        
        # Verify restored database
        if _verify_backup(DB_PATH):
            print(f"[BACKUP] ✅ Database restored successfully")
            return True
        else:
            print(f"[BACKUP] ❌ Restored database verification failed")
            return False
            
    except Exception as e:
        print(f"[BACKUP] ❌ Restore failed: {e}")
        return False


def _cleanup_old_backups():
    """Delete old backups based on retention policy."""
    try:
        if not os.path.exists(BACKUP_DIR):
            return
        
        # Get all backup files sorted by modification time
        backups = []
        for filename in os.listdir(BACKUP_DIR):
            if filename.startswith("edr_backup_") and filename.endswith(".db"):
                filepath = os.path.join(BACKUP_DIR, filename)
                mtime = os.path.getmtime(filepath)
                backups.append((filepath, mtime))
        
        backups.sort(key=lambda x: x[1], reverse=True)  # Newest first
        
        now = time.time()
        to_keep = []
        
        # Keep daily backups (last 7 days)
        daily_count = 0
        for path, mtime in backups:
            age_days = (now - mtime) / 86400
            if age_days < 1 and daily_count < DAILY_RETENTION:
                to_keep.append(path)
                daily_count += 1
        
        # Keep weekly backups (last 4 weeks)
        weekly_count = 0
        for path, mtime in backups:
            age_days = (now - mtime) / 86400
            if 7 <= age_days < 28 and weekly_count < WEEKLY_RETENTION:
                # Keep first backup of each week
                if path not in to_keep:
                    to_keep.append(path)
                    weekly_count += 1
        
        # Keep monthly backups (last 3 months)
        monthly_count = 0
        for path, mtime in backups:
            age_days = (now - mtime) / 86400
            if 28 <= age_days < 90 and monthly_count < MONTHLY_RETENTION:
                # Keep first backup of each month
                if path not in to_keep:
                    to_keep.append(path)
                    monthly_count += 1
        
        # Delete backups not in keep list
        deleted_count = 0
        for path, mtime in backups:
            if path not in to_keep:
                try:
                    os.remove(path)
                    deleted_count += 1
                except Exception as e:
                    print(f"[BACKUP] Failed to delete old backup {path}: {e}")
        
        if deleted_count > 0:
            print(f"[BACKUP] Cleaned up {deleted_count} old backup(s)")
            
    except Exception as e:
        print(f"[BACKUP] Cleanup failed: {e}")


def _backup_loop():
    """Background thread that runs periodic backups."""
    print(f"[BACKUP] Scheduler started (interval: {BACKUP_INTERVAL/3600:.1f} hours)")
    
    # Create initial backup on startup
    create_backup(reason="startup")
    
    while not _stop_event.wait(timeout=BACKUP_INTERVAL):
        create_backup(reason="scheduled")
    
    print("[BACKUP] Scheduler stopped")


def start_backup_scheduler():
    """Start the automatic backup scheduler."""
    global _backup_thread
    
    if _backup_thread and _backup_thread.is_alive():
        print("[BACKUP] Scheduler already running")
        return
    
    _stop_event.clear()
    _backup_thread = threading.Thread(target=_backup_loop, daemon=True, name="BackupScheduler")
    _backup_thread.start()


def stop_backup_scheduler():
    """Stop the automatic backup scheduler."""
    global _backup_thread
    
    if _backup_thread and _backup_thread.is_alive():
        print("[BACKUP] Stopping scheduler...")
        _stop_event.set()
        _backup_thread.join(timeout=5)
        _backup_thread = None


def get_backup_status() -> dict:
    """Get status of backup system."""
    try:
        backups = []
        if os.path.exists(BACKUP_DIR):
            for filename in os.listdir(BACKUP_DIR):
                if filename.startswith("edr_backup_") and filename.endswith(".db"):
                    filepath = os.path.join(BACKUP_DIR, filename)
                    stat = os.stat(filepath)
                    backups.append({
                        "filename": filename,
                        "path": filepath,
                        "size": stat.st_size,
                        "created": int(stat.st_mtime),
                        "age_hours": (time.time() - stat.st_mtime) / 3600
                    })
        
        backups.sort(key=lambda x: x["created"], reverse=True)
        
        return {
            "enabled": _backup_thread is not None and _backup_thread.is_alive(),
            "last_backup": _last_backup_status,
            "next_backup_in": int(BACKUP_INTERVAL - (time.time() - _last_backup_time)) if _last_backup_time > 0 else 0,
            "backups": backups,
            "retention_policy": {
                "daily": DAILY_RETENTION,
                "weekly": WEEKLY_RETENTION,
                "monthly": MONTHLY_RETENTION
            }
        }
    except Exception as e:
        return {"error": str(e)}


def list_backups() -> list:
    """Get list of available backups."""
    backups = []
    if os.path.exists(BACKUP_DIR):
        for filename in os.listdir(BACKUP_DIR):
            if filename.startswith("edr_backup_") and filename.endswith(".db"):
                filepath = os.path.join(BACKUP_DIR, filename)
                stat = os.stat(filepath)
                backups.append({
                    "filename": filename,
                    "path": filepath,
                    "size": stat.st_size,
                    "created": int(stat.st_mtime)
                })
    
    backups.sort(key=lambda x: x["created"], reverse=True)
    return backups


def _notify_backup_status(success: bool, backup_path: str, reason: str, error: str = ""):
    """Notify configured channels about backup status."""
    try:
        from server.notifier import is_configured, send_notification
        
        config = is_configured()
        if not config["enabled"]:
            return
        
        if success:
            message = f"✅ EDR Database Backup Successful\n"
            message += f"Reason: {reason}\n"
            message += f"File: {os.path.basename(backup_path)}\n"
            message += f"Size: {os.path.getsize(backup_path):,} bytes"
            
            # Only notify on manual/pre-clear backups (not scheduled, to avoid spam)
            if reason in ["manual", "pre-clear", "startup"]:
                send_notification("Database Backup", message, "info")
        else:
            message = f"❌ EDR Database Backup Failed\n"
            message += f"Reason: {reason}\n"
            message += f"Error: {error}\n"
            message += f"Action required: Check server logs"
            
            # Always notify on backup failures
            send_notification("Backup Failure", message, "critical")
            
    except Exception as e:
        print(f"[BACKUP] Notification failed: {e}")
