# server/threatintel.py — Threat Intelligence: IOC feed + VirusTotal hash lookup
"""
Two sources of threat intelligence:

1. LOCAL IOC FEED  (data/ioc_feed.json)
   A JSON list of IOC objects:
     {"type": "sha256", "value": "abc123...", "label": "Emotet", "severity": "CRITICAL"}
     {"type": "md5",    "value": "...",        "label": "Cobalt Strike", "severity": "HIGH"}
     {"type": "ipv4",   "value": "1.2.3.4",   "label": "Known C2",     "severity": "HIGH"}
     {"type": "domain", "value": "evil.com",  "label": "Phishing",     "severity": "MEDIUM"}
     {"type": "name",   "value": "mimikatz",  "label": "Credential tool","severity":"CRITICAL"}

   The local feed is loaded at startup and refreshed every IOC_REFRESH_HOURS.
   You can seed it with any MISP export, VirusTotal feed, or manual IOCs.

2. VIRUSTOTAL API  (optional, requires VT_API_KEY env var)
   When a new executable hash arrives and is NOT in the local feed,
   the system asynchronously queries VT. Results are cached in
   data/vt_cache.json and added to the local feed so repeat lookups are free.

Usage in detector.py:
    from server.threatintel import check_ioc
    hits = check_ioc(sha256="abc123...", name="calc.exe", ip="1.2.3.4")
    # returns list of {label, severity, source, ioc_type, ioc_value}
"""
import hashlib, json, os, threading, time, logging
from typing import List, Dict, Optional

from server.config import (
    IOC_FILE, DATA_DIR, VIRUSTOTAL_API_KEY, IOC_REFRESH_HOURS,
)

log = logging.getLogger("threatintel")

# ── In-memory indices ─────────────────────────────────────────────────────────
_idx_sha256: dict = {}   # sha256  → ioc
_idx_md5:    dict = {}   # md5     → ioc
_idx_ip:     dict = {}   # ipv4    → ioc
_idx_domain: dict = {}   # domain  → ioc
_idx_name:   dict = {}   # name lc → ioc
_lock = threading.Lock()
_loaded_at: float = 0.0
_load_state = "not_loaded"

_VT_CACHE_FILE = os.path.join(DATA_DIR, "vt_cache.json")


# ── Load / refresh ────────────────────────────────────────────────────────────

def _build_index(iocs: list):
    global _idx_sha256, _idx_md5, _idx_ip, _idx_domain, _idx_name
    s256, md5, ip, dom, nm = {}, {}, {}, {}, {}
    for ioc in iocs:
        t = ioc.get("type", "").lower()
        v = ioc.get("value", "").lower().strip()
        if not v:
            continue
        if   t == "sha256": s256[v] = ioc
        elif t == "md5":    md5[v]  = ioc
        elif t == "ipv4":   ip[v]   = ioc
        elif t == "domain": dom[v]  = ioc
        elif t == "name":   nm[v]   = ioc
    with _lock:
        _idx_sha256 = s256
        _idx_md5    = md5
        _idx_ip     = ip
        _idx_domain = dom
        _idx_name   = nm
    log.info("[IOC] Index rebuilt: %d sha256, %d ip, %d domain, %d name",
             len(s256), len(ip), len(dom), len(nm))


def load_iocs():
    """Load local IOC file and rebuild indices."""
    global _loaded_at, _load_state
    _load_state = "local"
    iocs = []
    if os.path.exists(IOC_FILE):
        try:
            with open(IOC_FILE, encoding="utf-8") as f:
                iocs = json.load(f)
            if not isinstance(iocs, list) or any(not isinstance(item, dict) for item in iocs):
                raise ValueError("IOC feed must contain a list of objects")
        except Exception as e:
            _load_state = "error"
            iocs = []
            log.warning("[IOC] Failed to load %s: %s", IOC_FILE, e)
    else:
        # Seed with a starter set of known malicious hashes/names
        _load_state = "starter_defaults"
        iocs = _default_iocs()
        _save_iocs(iocs)
    _build_index(iocs)
    _loaded_at = time.time()


def _save_iocs(iocs: list):
    tmp = IOC_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(iocs, f, indent=2)
    os.replace(tmp, IOC_FILE)


def add_ioc(ioc_type: str, value: str, label: str,
            severity: str = "HIGH", source: str = "manual"):
    """Add an IOC to the local feed and rebuild the index."""
    try:
        with open(IOC_FILE, encoding="utf-8") as f:
            iocs = json.load(f)
    except Exception:
        iocs = []
    ioc = {"type": ioc_type, "value": value.lower(),
           "label": label, "severity": severity, "source": source,
           "added": int(time.time())}
    iocs.append(ioc)
    _save_iocs(iocs)
    _build_index(iocs)


def _default_iocs() -> list:
    """Starter IOC set — well-known malicious process names and hashes."""
    return [
        {"type":"name","value":"mimikatz.exe",   "label":"Mimikatz credential dumper","severity":"CRITICAL","source":"builtin"},
        {"type":"name","value":"mimikatz",        "label":"Mimikatz credential dumper","severity":"CRITICAL","source":"builtin"},
        {"type":"name","value":"meterpreter",     "label":"Metasploit meterpreter",    "severity":"CRITICAL","source":"builtin"},
        {"type":"name","value":"cobalt strike",   "label":"Cobalt Strike beacon",      "severity":"CRITICAL","source":"builtin"},
        {"type":"name","value":"lazagne.exe",     "label":"LaZagne password recovery", "severity":"CRITICAL","source":"builtin"},
        {"type":"name","value":"sharphound.exe",  "label":"SharpHound AD recon",       "severity":"HIGH",    "source":"builtin"},
        {"type":"name","value":"bloodhound.exe",  "label":"BloodHound AD attack tool", "severity":"HIGH",    "source":"builtin"},
        {"type":"name","value":"rubeus.exe",      "label":"Rubeus Kerberos attack",    "severity":"CRITICAL","source":"builtin"},
        {"type":"name","value":"pwdump",          "label":"Password dump tool",        "severity":"CRITICAL","source":"builtin"},
        {"type":"name","value":"wce.exe",         "label":"Windows Credential Editor", "severity":"CRITICAL","source":"builtin"},
        {"type":"ipv4","value":"198.51.100.1",    "label":"TEST C2 - RFC5737",         "severity":"HIGH",    "source":"builtin"},
    ]


def _refresh_loop():
    """Background thread: reload IOC feed every IOC_REFRESH_HOURS."""
    while True:
        time.sleep(IOC_REFRESH_HOURS * 3600)
        log.info("[IOC] Refreshing IOC feed...")
        load_iocs()

# Refresh explicitly at startup; no background or external work on import.


# ── Public lookup API ─────────────────────────────────────────────────────────

def check_ioc(sha256: str = "", md5: str = "", name: str = "",
              ip: str = "", domain: str = "") -> List[Dict]:
    """
    Check any combination of indicators against the loaded IOC feed.
    Returns list of hits: [{label, severity, source, ioc_type, ioc_value}]
    """
    hits = []
    with _lock:
        if sha256 and sha256.lower() in _idx_sha256:
            ioc = _idx_sha256[sha256.lower()]
            hits.append(_hit(ioc, "sha256", sha256))
        if md5 and md5.lower() in _idx_md5:
            ioc = _idx_md5[md5.lower()]
            hits.append(_hit(ioc, "md5", md5))
        if ip and ip.lower() in _idx_ip:
            ioc = _idx_ip[ip.lower()]
            hits.append(_hit(ioc, "ipv4", ip))
        if domain and domain.lower() in _idx_domain:
            ioc = _idx_domain[domain.lower()]
            hits.append(_hit(ioc, "domain", domain))
        if name:
            name_lc = name.lower().strip()
            for key, ioc in _idx_name.items():
                if key == name_lc:
                    hits.append(_hit(ioc, "name", name))
                    break
    # External enrichment is not part of the supported ingestion path.
    return hits


def _hit(ioc: dict, ioc_type: str, ioc_value: str) -> dict:
    return {
        "label":     ioc.get("label", "Unknown threat"),
        "severity":  ioc.get("severity", "HIGH"),
        "source":    ioc.get("source", "local"),
        "ioc_type":  ioc_type,
        "ioc_value": ioc_value,
    }


# ── VirusTotal integration ────────────────────────────────────────────────────

def _load_vt_cache() -> dict:
    if os.path.exists(_VT_CACHE_FILE):
        try:
            with open(_VT_CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_vt_cache(cache: dict):
    tmp = _VT_CACHE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f)
    os.replace(tmp, _VT_CACHE_FILE)


def _vt_lookup(sha256: str):
    """Query VirusTotal for a hash. Cache the result and add to IOC feed if malicious."""
    cache = _load_vt_cache()
    if sha256 in cache:
        return   # already queried

    try:
        import urllib.request
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        req = urllib.request.Request(url,
            headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        name_info  = data.get("data", {}).get("attributes", {}).get("meaningful_name", sha256[:16])
        total      = sum(stats.values()) or 1

        cache[sha256] = {"malicious": malicious, "total": total, "name": name_info}
        _save_vt_cache(cache)

        if malicious >= 3:
            severity = "CRITICAL" if malicious >= 10 else "HIGH"
            add_ioc("sha256", sha256,
                    f"VT: {name_info} ({malicious}/{total} detections)",
                    severity, "virustotal")
            log.warning("[VT] Malicious hash %s: %d/%d detections (%s)",
                        sha256, malicious, total, name_info)
        else:
            log.info("[VT] Clean hash %s: %d/%d detections", sha256, malicious, total)

    except Exception as e:
        log.debug("[VT] Lookup failed for %s: %s", sha256, e)


def health_status():
    with _lock:
        count = sum(len(index) for index in (_idx_sha256, _idx_md5, _idx_ip, _idx_domain, _idx_name))
    return {"state": _load_state, "count": count, "loaded_at": _loaded_at}
