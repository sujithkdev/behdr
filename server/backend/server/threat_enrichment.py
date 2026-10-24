"""
server/threat_enrichment.py — Auto Threat Intelligence Enrichment

Automatically enriches every alert with context from multiple sources:
- VirusTotal (malware analysis)
- AlienVault OTX (threat intel)
- Abuse.ch (malware feeds)
- Shodan (IP reputation)
- MISP (threat sharing platform)

Enrichment runs in background to avoid blocking alert pipeline.
Results cached for 24 hours to reduce API calls.

Environment variables:
    VT_API_KEY          - VirusTotal API key
    OTX_API_KEY         - AlienVault OTX key
    SHODAN_API_KEY      - Shodan API key
    MISP_URL            - MISP instance URL
    MISP_API_KEY        - MISP API key
"""

import os
import time
import json
import hashlib
import threading
import requests
from collections import defaultdict
from datetime import datetime, timedelta


# API Keys
VT_API_KEY = os.environ.get("VT_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
MISP_URL = os.environ.get("MISP_URL", "")
MISP_KEY = os.environ.get("MISP_API_KEY", "")

# Cache (in-memory, 24h TTL)
_enrichment_cache = {}
_cache_lock = threading.Lock()
CACHE_TTL = 86400  # 24 hours


def _cache_get(key):
    """Get from cache if not expired"""
    with _cache_lock:
        if key in _enrichment_cache:
            data, timestamp = _enrichment_cache[key]
            if time.time() - timestamp < CACHE_TTL:
                return data
            else:
                del _enrichment_cache[key]
        return None


def _cache_set(key, data):
    """Set cache entry"""
    with _cache_lock:
        _enrichment_cache[key] = (data, time.time())
        
        # Limit cache size (keep last 1000 entries)
        if len(_enrichment_cache) > 1000:
            # Remove oldest 200 entries
            sorted_keys = sorted(_enrichment_cache.items(), key=lambda x: x[1][1])
            for k, _ in sorted_keys[:200]:
                del _enrichment_cache[k]


def enrich_virustotal(sha256):
    """Query VirusTotal for file hash"""
    if not VT_API_KEY or not sha256:
        return {}
    
    # Check cache
    cache_key = f"vt:{sha256}"
    cached = _cache_get(cache_key)
    if cached:
        return cached
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VT_API_KEY}
        
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            
            result = {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total_engines": sum(stats.values()),
                "names": attrs.get("names", [])[:5],  # First 5 AV names
                "verdict": "MALWARE" if stats.get("malicious", 0) > 5 else 
                          "SUSPICIOUS" if stats.get("suspicious", 0) > 0 else "CLEAN",
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
            
            _cache_set(cache_key, result)
            return result
        
        elif resp.status_code == 404:
            result = {"source": "VirusTotal", "verdict": "UNKNOWN", "note": "Hash not found"}
            _cache_set(cache_key, result)
            return result
            
    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}
    
    return {}


def enrich_otx(sha256=None, ip=None, domain=None):
    """Query AlienVault OTX"""
    if not OTX_API_KEY:
        return {}
    
    # Determine indicator type
    if sha256:
        indicator_type = "file"
        indicator = sha256
    elif ip:
        indicator_type = "IPv4"
        indicator = ip
    elif domain:
        indicator_type = "domain"
        indicator = domain
    else:
        return {}
    
    # Check cache
    cache_key = f"otx:{indicator}"
    cached = _cache_get(cache_key)
    if cached:
        return cached
    
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            
            result = {
                "source": "AlienVault OTX",
                "pulse_count": len(pulses),
                "threat_names": [p.get("name", "") for p in pulses[:3]],  # Top 3
                "tags": list(set(tag for p in pulses for tag in p.get("tags", [])))[:5],
                "verdict": "THREAT" if pulses else "UNKNOWN",
                "link": f"https://otx.alienvault.com/indicator/{indicator_type}/{indicator}",
            }
            
            _cache_set(cache_key, result)
            return result
            
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}
    
    return {}


def enrich_abusech(sha256):
    """Query Abuse.ch MalwareBazaar"""
    if not sha256:
        return {}
    
    cache_key = f"abusech:{sha256}"
    cached = _cache_get(cache_key)
    if cached:
        return cached
    
    try:
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_info", "hash": sha256}
        
        resp = requests.post(url, data=data, timeout=10)
        
        if resp.status_code == 200:
            result_data = resp.json()
            
            if result_data.get("query_status") == "ok":
                info = result_data.get("data", [{}])[0]
                
                result = {
                    "source": "Abuse.ch MalwareBazaar",
                    "signature": info.get("signature"),
                    "file_type": info.get("file_type"),
                    "tags": info.get("tags", []),
                    "verdict": "MALWARE",
                    "link": f"https://bazaar.abuse.ch/sample/{sha256}/",
                }
                
                _cache_set(cache_key, result)
                return result
            else:
                result = {"source": "Abuse.ch", "verdict": "UNKNOWN"}
                _cache_set(cache_key, result)
                return result
                
    except Exception as e:
        return {"source": "Abuse.ch", "error": str(e)}
    
    return {}


def enrich_shodan(ip):
    """Query Shodan for IP reputation"""
    if not SHODAN_API_KEY or not ip:
        return {}
    
    cache_key = f"shodan:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        
        resp = requests.get(url, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            
            result = {
                "source": "Shodan",
                "country": data.get("country_name", "Unknown"),
                "org": data.get("org", "Unknown"),
                "ports": data.get("ports", [])[:10],  # First 10 ports
                "vulns": list(data.get("vulns", []))[:5],  # First 5 CVEs
                "tags": data.get("tags", []),
                "verdict": "SUSPICIOUS" if data.get("tags") or data.get("vulns") else "INFO",
                "link": f"https://www.shodan.io/host/{ip}",
            }
            
            _cache_set(cache_key, result)
            return result
            
    except Exception as e:
        return {"source": "Shodan", "error": str(e)}
    
    return {}


def enrich_misp(sha256=None, ip=None, domain=None):
    """Query MISP threat sharing platform"""
    if not MISP_URL or not MISP_KEY:
        return {}
    
    # Determine search value
    value = sha256 or ip or domain
    if not value:
        return {}
    
    cache_key = f"misp:{value}"
    cached = _cache_get(cache_key)
    if cached:
        return cached
    
    try:
        url = f"{MISP_URL}/attributes/restSearch"
        headers = {
            "Authorization": MISP_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        data = {"value": value, "limit": 5}
        
        resp = requests.post(url, headers=headers, json=data, timeout=10, verify=False)
        
        if resp.status_code == 200:
            result_data = resp.json()
            attributes = result_data.get("response", {}).get("Attribute", [])
            
            if attributes:
                events = [a.get("Event", {}).get("info", "") for a in attributes]
                
                result = {
                    "source": "MISP",
                    "event_count": len(attributes),
                    "events": events[:3],  # Top 3 events
                    "verdict": "THREAT",
                    "link": f"{MISP_URL}/events/index",
                }
                
                _cache_set(cache_key, result)
                return result
            else:
                result = {"source": "MISP", "verdict": "UNKNOWN"}
                _cache_set(cache_key, result)
                return result
                
    except Exception as e:
        return {"source": "MISP", "error": str(e)}
    
    return {}


def enrich_alert(alert):
    """
    Enrich alert with threat intelligence from all sources.
    Runs in parallel for speed.
    
    Args:
        alert: Alert dict with keys: process, sha256, system_id, reason, etc.
    
    Returns:
        dict with enrichment data
    """
    sha256 = alert.get("sha256", "")
    process = alert.get("process", "")
    
    # Extract IPs from alert (if any in reason or other fields)
    # This is a simple extraction - you might want more sophisticated parsing
    import re
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, str(alert))
    ip = ips[0] if ips else None
    
    enrichment = {
        "enriched_at": datetime.utcnow().isoformat(),
        "sources": [],
        "overall_verdict": "UNKNOWN",
        "confidence": 0,
        "recommendations": [],
    }
    
    # Run all enrichments in parallel
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        
        if sha256:
            futures["vt"] = executor.submit(enrich_virustotal, sha256)
            futures["otx_hash"] = executor.submit(enrich_otx, sha256=sha256)
            futures["abusech"] = executor.submit(enrich_abusech, sha256)
            futures["misp_hash"] = executor.submit(enrich_misp, sha256=sha256)
        
        if ip:
            futures["shodan"] = executor.submit(enrich_shodan, ip)
            futures["otx_ip"] = executor.submit(enrich_otx, ip=ip)
            futures["misp_ip"] = executor.submit(enrich_misp, ip=ip)
        
        # Collect results
        for name, future in futures.items():
            try:
                result = future.result(timeout=15)
                if result:
                    enrichment["sources"].append(result)
            except Exception as e:
                pass
    
    # Calculate overall verdict
    verdicts = [s.get("verdict", "UNKNOWN") for s in enrichment["sources"]]
    verdict_priority = {"MALWARE": 4, "THREAT": 3, "SUSPICIOUS": 2, "INFO": 1, "CLEAN": 0, "UNKNOWN": 0}
    
    if verdicts:
        enrichment["overall_verdict"] = max(verdicts, key=lambda v: verdict_priority.get(v, 0))
    
    # Calculate confidence (0-100)
    malware_count = sum(1 for v in verdicts if v in ["MALWARE", "THREAT"])
    total_sources = len(enrichment["sources"])
    
    if total_sources > 0:
        enrichment["confidence"] = int((malware_count / total_sources) * 100)
    
    # Generate recommendations
    if enrichment["overall_verdict"] in ["MALWARE", "THREAT"]:
        enrichment["recommendations"] = [
            "Isolate endpoint immediately",
            "Scan for additional malware",
            "Check for persistence mechanisms",
            "Review recent file modifications",
            "Investigate lateral movement",
        ]
    elif enrichment["overall_verdict"] == "SUSPICIOUS":
        enrichment["recommendations"] = [
            "Monitor endpoint for further activity",
            "Check process network connections",
            "Review parent process chain",
        ]
    
    return enrichment


def enrich_alert_async(alert_id, alert):
    """
    Enrich alert in background thread (non-blocking).
    Updates database with enrichment data.
    """
    def _worker():
        try:
            enrichment = enrich_alert(alert)
            
            # Save to database
            from server.database.storage import _conn
            conn = _conn()
            
            # Add enrichment column if it doesn't exist
            try:
                conn.execute("ALTER TABLE alerts ADD COLUMN enrichment TEXT")
            except Exception:
                pass  # Column already exists
            
            conn.execute(
                "UPDATE alerts SET enrichment = ? WHERE id = ?",
                (json.dumps(enrichment), alert_id)
            )
            conn.commit()
            
            print(f"[ENRICH] Alert #{alert_id}: {enrichment['overall_verdict']} "
                  f"(confidence {enrichment['confidence']}%)")
            
        except Exception as e:
            print(f"[ENRICH] Error enriching alert #{alert_id}: {e}")
    
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


def get_enrichment(alert_id):
    """Get enrichment data for an alert"""
    from server.database.storage import _conn
    conn = _conn()
    
    row = conn.execute(
        "SELECT enrichment FROM alerts WHERE id = ?",
        (alert_id,)
    ).fetchone()
    
    if row and row["enrichment"]:
        try:
            return json.loads(row["enrichment"])
        except Exception:
            return None
    
    return None


# Test function
if __name__ == "__main__":
    # Test enrichment
    test_alert = {
        "process": "suspicious.exe",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # Known malware hash
        "reason": "Connected to 45.142.212.61",
    }
    
    print("Testing threat enrichment...")
    result = enrich_alert(test_alert)
    print(json.dumps(result, indent=2))
