"""
server/core/yara_engine.py — YARA Signature-Based Detection Engine

Integrates industry-standard YARA rules for traditional signature matching:
- Scans executables against malware signatures
- Memory scanning (fileless malware detection)
- Auto-downloads rule packs from GitHub
- Fast caching (don't rescan same file)
- Rule management (enable/disable rules)

Installation:
    pip install yara-python

Rule Sources (auto-downloaded):
    - YaraRules Project (github.com/Yara-Rules/rules)
    - Awesome YARA (github.com/InQuest/awesome-yara)
    - ReversingLabs YARA rules
    - Custom community rules

Usage:
    from server.core.yara_engine import scan_file, scan_memory
    
    # Scan file
    matches = scan_file("/path/to/suspicious.exe")
    if matches:
        print(f"Detected: {matches[0]['rule']}")
    
    # Scan process memory
    matches = scan_memory(pid=1234)
"""

import os
import time
import json
import hashlib
import threading
import requests
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[YARA] yara-python not installed. Run: pip install yara-python")

# Paths
RULES_DIR = Path(__file__).parent.parent.parent / "rules" / "yara"
COMPILED_RULES_FILE = RULES_DIR / "compiled_rules.yrc"
RULES_INDEX_FILE = RULES_DIR / "rules_index.json"
STATS_FILE = RULES_DIR / "detection_stats.json"

# Cache
_scan_cache = {}  # sha256 -> (matches, timestamp)
_cache_lock = threading.Lock()
CACHE_TTL = 86400  # 24 hours

# Compiled rules
_compiled_rules = None
_rules_lock = threading.Lock()
_rules_index = {}

# Statistics
_stats = defaultdict(lambda: {"hits": 0, "last_hit": None})
_stats_lock = threading.Lock()

# Auto-update
_last_update_check = 0
UPDATE_INTERVAL = 86400  # Check daily


def is_available():
    """Check if YARA is available"""
    return YARA_AVAILABLE


def ensure_rules_dir():
    """Create rules directory if it doesn't exist"""
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create README if missing
    readme = RULES_DIR / "README.md"
    if not readme.exists():
        readme.write_text("""# YARA Rules Directory

Place your YARA rule files (.yar, .yara) in this directory.

## Auto-Download Rules

Run to download free rule packs:
```bash
python -c "from server.core.yara_engine import download_rule_packs; download_rule_packs()"
```

## Rule Sources

Free rule collections:
- YaraRules Project: https://github.com/Yara-Rules/rules
- Awesome YARA: https://github.com/InQuest/awesome-yara
- ReversingLabs: https://github.com/reversinglabs/reversinglabs-yara-rules

## Custom Rules

Create your own rules:
```yara
rule MyMalware {
    meta:
        description = "Detects my custom malware"
        author = "Your Name"
        date = "2026-08-15"
    
    strings:
        $s1 = "malicious_string" ascii
        $s2 = { 4D 5A 90 00 }  // PE header
    
    condition:
        $s1 or $s2
}
```

Save as `custom_rules.yar` in this directory.
""")


def download_rule_packs():
    """Download free YARA rule packs from GitHub"""
    if not YARA_AVAILABLE:
        print("[YARA] yara-python not installed")
        return False
    
    ensure_rules_dir()
    
    print("[YARA] Downloading community rule packs...")
    
    # Rule sources (carefully selected, production-ready rules)
    rule_sources = [
        {
            "name": "malware_index",
            "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar",
            "description": "EICAR test file detection"
        },
        {
            "name": "ransomware_rules",
            "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/RANSOM_Ryuk.yar",
            "description": "Ryuk ransomware detection"
        },
        {
            "name": "apt_rules",
            "url": "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_APT29.yar",
            "description": "APT29 detection rules"
        },
        {
            "name": "maldoc_rules",
            "url": "https://raw.githubusercontent.com/InQuest/yara-rules/master/labs.inquest.net/maldocs.rule",
            "description": "Malicious document detection"
        },
        {
            "name": "webshell_rules",
            "url": "https://raw.githubusercontent.com/InQuest/yara-rules/master/labs.inquest.net/webshells.rule",
            "description": "Web shell detection"
        },
    ]
    
    success_count = 0
    
    for source in rule_sources:
        try:
            print(f"[YARA] Downloading {source['name']}...")
            resp = requests.get(source["url"], timeout=30)
            
            if resp.status_code == 200:
                rule_file = RULES_DIR / f"{source['name']}.yar"
                rule_file.write_text(resp.text)
                print(f"[YARA] ✓ {source['name']}: {source['description']}")
                success_count += 1
            else:
                print(f"[YARA] ✗ {source['name']}: HTTP {resp.status_code}")
                
        except Exception as e:
            print(f"[YARA] ✗ {source['name']}: {e}")
    
    print(f"\n[YARA] Downloaded {success_count}/{len(rule_sources)} rule packs")
    
    if success_count > 0:
        compile_rules()
        return True
    
    return False


def compile_rules():
    """Compile all YARA rules in rules directory"""
    if not YARA_AVAILABLE:
        return False
    
    ensure_rules_dir()
    
    # Find all .yar and .yara files
    rule_files = list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara"))
    
    if not rule_files:
        print("[YARA] No rule files found. Run download_rule_packs() first.")
        return False
    
    print(f"[YARA] Compiling {len(rule_files)} rule files...")
    
    # Build namespace dict for compilation
    namespaces = {}
    rules_index = {}
    
    for rule_file in rule_files:
        namespace = rule_file.stem
        try:
            namespaces[namespace] = str(rule_file)
            
            # Parse rules to build index (metadata extraction)
            with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Simple rule name extraction (not perfect but works)
                import re
                rule_names = re.findall(r'rule\s+(\w+)', content)
                for rule_name in rule_names:
                    rules_index[rule_name] = {
                        "file": namespace,
                        "enabled": True,
                        "hits": 0,
                    }
                    
        except Exception as e:
            print(f"[YARA] Warning: Could not parse {rule_file}: {e}")
    
    try:
        # Compile all rules
        rules = yara.compile(filepaths=namespaces)
        
        # Save compiled rules (faster loading)
        rules.save(str(COMPILED_RULES_FILE))
        
        # Save rules index
        with open(RULES_INDEX_FILE, 'w') as f:
            json.dump(rules_index, f, indent=2)
        
        global _compiled_rules, _rules_index
        with _rules_lock:
            _compiled_rules = rules
            _rules_index = rules_index
        
        print(f"[YARA] ✓ Compiled {len(rules_index)} rules from {len(rule_files)} files")
        print(f"[YARA] ✓ Saved to {COMPILED_RULES_FILE}")
        return True
        
    except Exception as e:
        print(f"[YARA] Compilation failed: {e}")
        return False


def load_compiled_rules():
    """Load pre-compiled YARA rules"""
    global _compiled_rules, _rules_index
    
    if not YARA_AVAILABLE:
        return False
    
    # Check if compiled rules exist
    if not COMPILED_RULES_FILE.exists():
        print("[YARA] No compiled rules found. Downloading rule packs...")
        if not download_rule_packs():
            return False
    
    try:
        with _rules_lock:
            _compiled_rules = yara.load(str(COMPILED_RULES_FILE))
        
        # Load rules index
        if RULES_INDEX_FILE.exists():
            with open(RULES_INDEX_FILE, 'r') as f:
                _rules_index = json.load(f)
        
        print(f"[YARA] ✓ Loaded {len(_rules_index)} compiled rules")
        return True
        
    except Exception as e:
        print(f"[YARA] Failed to load compiled rules: {e}")
        print("[YARA] Attempting to recompile...")
        return compile_rules()


def _get_rules():
    """Get compiled rules (lazy load)"""
    global _compiled_rules
    
    if _compiled_rules is None:
        load_compiled_rules()
    
    return _compiled_rules


def _cache_get(sha256):
    """Get scan result from cache"""
    with _cache_lock:
        if sha256 in _scan_cache:
            matches, timestamp = _scan_cache[sha256]
            if time.time() - timestamp < CACHE_TTL:
                return matches
            else:
                del _scan_cache[sha256]
    return None


def _cache_set(sha256, matches):
    """Cache scan result"""
    with _cache_lock:
        _scan_cache[sha256] = (matches, time.time())
        
        # Limit cache size
        if len(_scan_cache) > 10000:
            # Remove oldest 20%
            sorted_items = sorted(_scan_cache.items(), key=lambda x: x[1][1])
            for k, _ in sorted_items[:2000]:
                del _scan_cache[k]


def _update_stats(rule_name):
    """Update detection statistics"""
    with _stats_lock:
        _stats[rule_name]["hits"] += 1
        _stats[rule_name]["last_hit"] = datetime.utcnow().isoformat()
        
        # Save stats periodically (every 10 hits)
        if sum(s["hits"] for s in _stats.values()) % 10 == 0:
            try:
                with open(STATS_FILE, 'w') as f:
                    json.dump(dict(_stats), f, indent=2)
            except Exception:
                pass


def scan_file(file_path):
    """
    Scan file with YARA rules.
    
    Args:
        file_path: Path to file to scan
    
    Returns:
        List of matches: [{"rule": "MalwareName", "tags": [...], "meta": {...}}]
        Empty list if no matches
        None if error
    """
    if not YARA_AVAILABLE:
        return None
    
    rules = _get_rules()
    if rules is None:
        return None
    
    # Check cache (by file hash)
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        cached = _cache_get(file_hash)
        if cached is not None:
            return cached
            
    except Exception:
        file_hash = None
    
    # Scan file
    try:
        matches = rules.match(file_path)
        
        result = []
        for match in matches:
            # Check if rule is enabled
            if match.rule in _rules_index and not _rules_index[match.rule].get("enabled", True):
                continue
            
            result.append({
                "rule": match.rule,
                "tags": list(match.tags),
                "meta": dict(match.meta),
                "namespace": match.namespace,
                "strings": [{"offset": s[0], "identifier": s[1], "data": s[2][:100]} 
                           for s in match.strings[:5]],  # First 5 strings
            })
            
            # Update stats
            _update_stats(match.rule)
        
        # Cache result
        if file_hash:
            _cache_set(file_hash, result)
        
        return result
        
    except Exception as e:
        print(f"[YARA] Scan error: {e}")
        return None


def scan_memory(pid):
    """
    Scan process memory with YARA rules (requires admin/root).
    
    Args:
        pid: Process ID to scan
    
    Returns:
        List of matches (same format as scan_file)
        None if error or not supported
    """
    if not YARA_AVAILABLE:
        return None
    
    rules = _get_rules()
    if rules is None:
        return None
    
    try:
        # Scan process memory
        matches = rules.match(pid=pid)
        
        result = []
        for match in matches:
            if match.rule in _rules_index and not _rules_index[match.rule].get("enabled", True):
                continue
            
            result.append({
                "rule": match.rule,
                "tags": list(match.tags),
                "meta": dict(match.meta),
                "namespace": match.namespace,
                "strings": [{"offset": s[0], "identifier": s[1]} 
                           for s in match.strings[:5]],
            })
            
            _update_stats(match.rule)
        
        return result
        
    except Exception as e:
        print(f"[YARA] Memory scan error for PID {pid}: {e}")
        return None


def scan_data(data, timeout=60):
    """
    Scan raw bytes with YARA rules.
    
    Args:
        data: Bytes to scan
        timeout: Scan timeout in seconds
    
    Returns:
        List of matches (same format as scan_file)
    """
    if not YARA_AVAILABLE:
        return None
    
    rules = _get_rules()
    if rules is None:
        return None
    
    try:
        matches = rules.match(data=data, timeout=timeout)
        
        result = []
        for match in matches:
            if match.rule in _rules_index and not _rules_index[match.rule].get("enabled", True):
                continue
            
            result.append({
                "rule": match.rule,
                "tags": list(match.tags),
                "meta": dict(match.meta),
                "namespace": match.namespace,
            })
            
            _update_stats(match.rule)
        
        return result
        
    except Exception as e:
        print(f"[YARA] Data scan error: {e}")
        return None


def get_rules_list():
    """Get list of all loaded rules with stats"""
    if not _rules_index:
        load_compiled_rules()
    
    result = []
    for rule_name, info in _rules_index.items():
        stats = _stats.get(rule_name, {})
        result.append({
            "rule": rule_name,
            "file": info.get("file", "unknown"),
            "enabled": info.get("enabled", True),
            "hits": stats.get("hits", 0),
            "last_hit": stats.get("last_hit"),
        })
    
    return sorted(result, key=lambda x: x["hits"], reverse=True)


def enable_rule(rule_name, enabled=True):
    """Enable or disable a rule"""
    if rule_name in _rules_index:
        _rules_index[rule_name]["enabled"] = enabled
        
        # Save index
        try:
            with open(RULES_INDEX_FILE, 'w') as f:
                json.dump(_rules_index, f, indent=2)
            return True
        except Exception as e:
            print(f"[YARA] Failed to save rules index: {e}")
            return False
    
    return False


def get_stats():
    """Get detection statistics"""
    return {
        "total_rules": len(_rules_index),
        "enabled_rules": sum(1 for r in _rules_index.values() if r.get("enabled", True)),
        "total_detections": sum(s["hits"] for s in _stats.values()),
        "cache_size": len(_scan_cache),
        "top_rules": sorted(
            [(name, data["hits"]) for name, data in _stats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10],
    }


# Initialize on import
if YARA_AVAILABLE:
    # Load compiled rules in background
    def _init():
        try:
            load_compiled_rules()
        except Exception as e:
            print(f"[YARA] Initialization error: {e}")
    
    threading.Thread(target=_init, daemon=True).start()


# Test function
if __name__ == "__main__":
    print("YARA Engine Test")
    print("=" * 60)
    
    if not YARA_AVAILABLE:
        print("✗ yara-python not installed")
        print("  Run: pip install yara-python")
    else:
        print("✓ yara-python installed")
        
        # Test EICAR
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        
        print("\nDownloading rules...")
        download_rule_packs()
        
        print("\nTesting EICAR detection...")
        matches = scan_data(eicar)
        
        if matches:
            print(f"✓ Detected: {len(matches)} rule(s)")
            for m in matches:
                print(f"  - {m['rule']}: {m['meta'].get('description', 'No description')}")
        else:
            print("✗ No detection (rules may not include EICAR)")
        
        print("\nStatistics:")
        stats = get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
