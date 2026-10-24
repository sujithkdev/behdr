"""Optional local hash intelligence. No bundled coverage or automatic refresh is guaranteed."""

import os
import logging
from contextlib import closing
import time
import json
import sqlite3
import threading
import requests
from pathlib import Path
from datetime import datetime, timedelta


# Paths
from server.config import DATA_DIR as SERVER_DATA_DIR
DATA_DIR = Path(SERVER_DATA_DIR)
HASH_DB_FILE = DATA_DIR / "malware_hashes.db"
UPDATE_LOG_FILE = DATA_DIR / "hash_db_updates.log"

# Auto-update settings
LAST_UPDATE_FILE = DATA_DIR / ".hash_db_last_update"
UPDATE_INTERVAL = 86400  # 24 hours

# Thread-safe connection pool
_conn_pool = threading.local()


def _get_conn():
    """Get thread-local database connection"""
    if not HASH_DB_FILE.exists():
        raise FileNotFoundError("Hash database is not provisioned")
    if not hasattr(_conn_pool, 'conn'):
        _conn_pool.conn = sqlite3.connect(HASH_DB_FILE.resolve().as_uri() + "?mode=rw", uri=True, check_same_thread=False)
        _conn_pool.conn.row_factory = sqlite3.Row
    return _conn_pool.conn


def init_hash_db():
    """Initialize hash database schema"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    if not HASH_DB_FILE.exists():
        sqlite3.connect(str(HASH_DB_FILE)).close()
    conn = _get_conn()
    
    # Create tables
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malware_hashes (
            sha256 TEXT PRIMARY KEY,
            family TEXT,
            tags TEXT,
            first_seen INTEGER,
            source TEXT,
            signature TEXT,
            file_type TEXT
        )
    """)
    
    # Create index for fast lookups
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON malware_hashes(sha256)")
    
    # Statistics table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hash_stats (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    conn.commit()
    
    # Check if database is empty
    count = conn.execute("SELECT COUNT(*) as cnt FROM malware_hashes").fetchone()["cnt"]
    
    if count == 0:
        print(f"[HASH-DB] Database initialized (empty)")
        return True
    else:
        print(f"[HASH-DB] Database ready ({count:,} hashes)")
        return True


def check_hash(sha256):
    """
    Check if hash exists in malware database.
    
    Args:
        sha256: SHA-256 hash (lowercase hex string)
    
    Returns:
        dict with malware info if found:
            {
                "sha256": "...",
                "family": "Emotet",
                "tags": ["trojan", "loader"],
                "first_seen": 1692115200,
                "source": "MalwareBazaar",
                "signature": "Win32.Emotet.A",
                "file_type": "exe"
            }
        None if not found
    """
    if not sha256 or len(sha256) != 64:
        return None
    
    sha256 = sha256.lower()
    
    global _last_error
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM malware_hashes WHERE sha256 = ?",
            (sha256,)
        ).fetchone()
        _last_error = None
        
        if row:
            return {
                "sha256": row["sha256"],
                "family": row["family"] or "Unknown",
                "tags": json.loads(row["tags"]) if row["tags"] else [],
                "first_seen": row["first_seen"],
                "source": row["source"],
                "signature": row["signature"],
                "file_type": row["file_type"],
            }
        
        return None
        
    except Exception as e:
        if _last_error != str(e):
            logging.getLogger(__name__).exception("Hash intelligence lookup unavailable")
        _last_error = str(e)
        return None


def add_hash(sha256, family="Unknown", tags=None, source="Manual", signature=None, file_type=None):
    """Add a hash to the database"""
    if not sha256 or len(sha256) != 64:
        return False
    
    sha256 = sha256.lower()
    tags = tags or []
    
    try:
        conn = _get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO malware_hashes 
            (sha256, family, tags, first_seen, source, signature, file_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            sha256,
            family,
            json.dumps(tags),
            int(time.time()),
            source,
            signature,
            file_type
        ))
        conn.commit()
        return True
        
    except Exception as e:
        print(f"[HASH-DB] Add hash error: {e}")
        return False


def download_malwarebazaar_hashes(limit=100000):
    """
    Download recent malware hashes from MalwareBazaar.
    
    Args:
        limit: Maximum number of hashes to download (default 100k)
    
    Returns:
        Number of hashes added
    """
    print(f"[HASH-DB] Downloading from MalwareBazaar (limit: {limit:,})...")
    
    url = "https://mb-api.abuse.ch/api/v1/"
    
    # Get recent malware (last 100 days)
    try:
        data = {"query": "get_recent", "selector": "100days"}
        resp = requests.post(url, data=data, timeout=60)
        
        if resp.status_code != 200:
            print(f"[HASH-DB] MalwareBazaar API error: HTTP {resp.status_code}")
            return 0
        
        result = resp.json()
        
        if result.get("query_status") != "ok":
            print(f"[HASH-DB] MalwareBazaar query failed: {result.get('query_status')}")
            return 0
        
        samples = result.get("data", [])
        print(f"[HASH-DB] Retrieved {len(samples)} samples")
        
        # Add to database
        conn = _get_conn()
        added = 0
        
        for sample in samples[:limit]:
            try:
                sha256 = sample.get("sha256_hash", "").lower()
                if not sha256 or len(sha256) != 64:
                    continue
                
                # Check if already exists
                existing = conn.execute(
                    "SELECT sha256 FROM malware_hashes WHERE sha256 = ?",
                    (sha256,)
                ).fetchone()
                
                if existing:
                    continue
                
                family = sample.get("signature") or "Unknown"
                tags = sample.get("tags", [])
                if isinstance(tags, str):
                    tags = [tags]
                
                conn.execute("""
                    INSERT INTO malware_hashes
                    (sha256, family, tags, first_seen, source, signature, file_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    sha256,
                    family,
                    json.dumps(tags),
                    int(time.time()),
                    "MalwareBazaar",
                    sample.get("signature"),
                    sample.get("file_type")
                ))
                
                added += 1
                
                # Commit in batches
                if added % 1000 == 0:
                    conn.commit()
                    print(f"[HASH-DB] Progress: {added:,} hashes added")
                    
            except Exception as e:
                print(f"[HASH-DB] Error adding sample: {e}")
                continue
        
        conn.commit()
        print(f"[HASH-DB] ✓ Added {added:,} new hashes from MalwareBazaar")
        return added
        
    except Exception as e:
        print(f"[HASH-DB] MalwareBazaar download error: {e}")
        return 0


def download_urlhaus_hashes():
    """Download malicious file hashes from URLhaus"""
    print("[HASH-DB] Downloading from URLhaus...")
    
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    
    try:
        resp = requests.get(url, timeout=60)
        
        if resp.status_code != 200:
            print(f"[HASH-DB] URLhaus error: HTTP {resp.status_code}")
            return 0
        
        lines = resp.text.strip().split('\n')
        conn = _get_conn()
        added = 0
        
        for line in lines:
            if line.startswith('#') or not line.strip():
                continue
            
            try:
                # CSV format: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
                parts = line.split(',', 7)
                if len(parts) < 7:
                    continue
                
                # Extract threat info
                threat = parts[4].strip('"')
                tags_str = parts[5].strip('"')
                
                # URLhaus doesn't provide hashes directly in CSV
                # Skip for now or implement URL-to-hash resolution
                
            except Exception:
                continue
        
        conn.commit()
        print(f"[HASH-DB] ✓ Added {added} hashes from URLhaus")
        return added
        
    except Exception as e:
        print(f"[HASH-DB] URLhaus download error: {e}")
        return 0


def download_threatfox_iocs():
    """Download IOCs from ThreatFox"""
    print("[HASH-DB] Downloading from ThreatFox...")
    
    url = "https://threatfox-api.abuse.ch/api/v1/"
    
    try:
        # Get recent IOCs
        data = {"query": "get_iocs", "days": 7}
        resp = requests.post(url, json=data, timeout=60)
        
        if resp.status_code != 200:
            print(f"[HASH-DB] ThreatFox error: HTTP {resp.status_code}")
            return 0
        
        result = resp.json()
        
        if result.get("query_status") != "ok":
            print(f"[HASH-DB] ThreatFox query failed")
            return 0
        
        iocs = result.get("data", [])
        conn = _get_conn()
        added = 0
        
        for ioc in iocs:
            try:
                # Only process file hashes
                ioc_type = ioc.get("ioc_type", "")
                if "sha256" not in ioc_type.lower():
                    continue
                
                sha256 = ioc.get("ioc", "").lower()
                if not sha256 or len(sha256) != 64:
                    continue
                
                # Check if exists
                existing = conn.execute(
                    "SELECT sha256 FROM malware_hashes WHERE sha256 = ?",
                    (sha256,)
                ).fetchone()
                
                if existing:
                    continue
                
                family = ioc.get("malware_alias") or ioc.get("malware") or "Unknown"
                tags = ioc.get("tags", [])
                
                conn.execute("""
                    INSERT INTO malware_hashes
                    (sha256, family, tags, first_seen, source, signature, file_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    sha256,
                    family,
                    json.dumps(tags) if isinstance(tags, list) else json.dumps([tags]),
                    int(time.time()),
                    "ThreatFox",
                    family,
                    None
                ))
                
                added += 1
                
            except Exception as e:
                print(f"[HASH-DB] Error adding ThreatFox IOC: {e}")
                continue
        
        conn.commit()
        print(f"[HASH-DB] ✓ Added {added} hashes from ThreatFox")
        return added
        
    except Exception as e:
        print(f"[HASH-DB] ThreatFox download error: {e}")
        return 0


def update_hash_db(force=False):
    """
    Update hash database from all sources.
    
    Args:
        force: Force update even if recently updated
    
    Returns:
        Total number of new hashes added
    """
    # Check last update time
    if not force and LAST_UPDATE_FILE.exists():
        last_update = float(LAST_UPDATE_FILE.read_text().strip())
        if time.time() - last_update < UPDATE_INTERVAL:
            print(f"[HASH-DB] Updated recently ({int((time.time() - last_update) / 3600)} hours ago)")
            return 0
    
    print("[HASH-DB] Starting update from all sources...")
    start_time = time.time()
    
    # Initialize if needed
    init_hash_db()
    
    total_added = 0
    
    # Download from sources
    total_added += download_malwarebazaar_hashes(limit=100000)
    total_added += download_threatfox_iocs()
    # URLhaus doesn't provide hashes easily - skip for now
    
    # Update last update timestamp
    LAST_UPDATE_FILE.write_text(str(time.time()))
    
    # Update stats
    conn = _get_conn()
    total_hashes = conn.execute("SELECT COUNT(*) as cnt FROM malware_hashes").fetchone()["cnt"]
    
    conn.execute("""
        INSERT OR REPLACE INTO hash_stats (key, value)
        VALUES ('total_hashes', ?), ('last_update', ?), ('last_added', ?)
    """, (str(total_hashes), str(int(time.time())), str(total_added)))
    conn.commit()
    
    elapsed = time.time() - start_time
    print(f"[HASH-DB] Update complete: {total_added:,} new hashes added in {elapsed:.1f}s")
    print(f"[HASH-DB] Total database size: {total_hashes:,} hashes")
    
    return total_added


def get_stats():
    """Get hash database statistics"""
    try:
        conn = _get_conn()
        
        total = conn.execute("SELECT COUNT(*) as cnt FROM malware_hashes").fetchone()["cnt"]
        
        # Top families
        top_families = conn.execute("""
            SELECT family, COUNT(*) as cnt
            FROM malware_hashes
            WHERE family != 'Unknown'
            GROUP BY family
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()
        
        # Sources
        sources = conn.execute("""
            SELECT source, COUNT(*) as cnt
            FROM malware_hashes
            GROUP BY source
        """).fetchall()
        
        # Last update
        last_update_row = conn.execute("""
            SELECT value FROM hash_stats WHERE key = 'last_update'
        """).fetchone()
        
        last_update = None
        if last_update_row:
            last_update = datetime.fromtimestamp(int(last_update_row["value"])).isoformat()
        
        return {
            "total_hashes": total,
            "top_families": [{"family": r["family"], "count": r["cnt"]} for r in top_families],
            "sources": [{"source": r["source"], "count": r["cnt"]} for r in sources],
            "last_update": last_update,
        }
        
    except Exception as e:
        print(f"[HASH-DB] Stats error: {e}")
        return {"total_hashes": 0, "top_families": [], "sources": [], "last_update": None}


def start_auto_updater():
    """Start background thread that updates hash DB daily"""
    def _updater():
        while True:
            try:
                time.sleep(UPDATE_INTERVAL)
                update_hash_db()
            except Exception as e:
                print(f"[HASH-DB] Auto-updater error: {e}")
    
    thread = threading.Thread(target=_updater, daemon=True, name="HashDBUpdater")
    thread.start()
    print("[HASH-DB] Auto-updater started (checks daily)")


# Initialize on import
# Initialization is explicit; importing must not write to the filesystem.


# Test function
if __name__ == "__main__":
    print("Malware Hash Database Test")
    print("=" * 60)
    
    # Test initialization
    init_hash_db()
    
    # Test update
    print("\nUpdating database...")
    added = update_hash_db(force=True)
    print(f"Added: {added:,} hashes")
    
    # Test lookup
    print("\nTesting lookup...")
    
    # Add test hash
    test_hash = "0" * 64
    add_hash(test_hash, family="TestMalware", tags=["test"], source="Test")
    
    result = check_hash(test_hash)
    if result:
        print(f"✓ Test hash found: {result['family']}")
    else:
        print("✗ Test hash not found")
    
    # Statistics
    print("\nStatistics:")
    stats = get_stats()
    print(f"  Total hashes: {stats['total_hashes']:,}")
    print(f"  Last update: {stats['last_update']}")
    print(f"\n  Top families:")
    for fam in stats['top_families'][:5]:
        print(f"    {fam['family']}: {fam['count']:,}")


_last_error = None


def health_status():
    """Inspect without creating a missing database or exposing filesystem errors."""
    if not HASH_DB_FILE.exists():
        return {"state": "missing", "count": 0, "automatic_refresh": False}
    try:
        with closing(sqlite3.connect(HASH_DB_FILE.resolve().as_uri() + '?mode=ro', uri=True)) as conn:
            count = conn.execute('SELECT COUNT(*) FROM malware_hashes').fetchone()[0]
        return {"state": "error" if _last_error else ("ready" if count else "empty"),
                "count": count, "automatic_refresh": False}
    except (sqlite3.Error, OSError):
        return {"state": "error", "count": None, "automatic_refresh": False}
