# server/core/detector.py — 7-Layer EDR Detection Engine
"""
Layer 1: Exact Behaviour Chain Rules  (YAML, HIGH confidence, fires immediately)
Layer 2: Heuristic Weighted Scoring   (YAML, additive multi-signal)
Layer 3: Parent-Child Analysis        (YAML, suspicious/safe pair lookup)
Layer 4: MITRE ATT&CK Intent Classif. (YAML, keyword threshold scoring)
Layer 5: ML Anomaly Fallback          (Isolation Forest, capped at HIGH)
Layer 6: Network Behaviour Analysis   (C2 beaconing, lateral movement ports)
Layer 7: File & Registry Analysis     (ransomware patterns, ransom notes)

Automatic response is disabled in this release. Destructive actions require
an authenticated operator and endpoint process-identity checks.
"""

import os, re, time, datetime, threading, yaml, math
import numpy as np
from contextvars import ContextVar
from server.config import EXPERIMENTAL_ML
_current_event = ContextVar('event', default=None)
_persisted_alerts = ContextVar('alerts', default=None)
from collections import defaultdict, deque
from typing import List, Tuple

from server.config import (
    OFFICE_APPS, PROCESS_WHITELIST, CRITICAL_PAIRS,
    MALICIOUS_TOOLS, LOLBINS, SCRIPT_ENGINES, BROWSERS,
    RANSOMWARE_TOOLS, CREDENTIAL_TOOLS, NEVER_KILL,
    RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM,
    ML_TRAIN_AFTER, ML_RETRAIN_EVERY, ML_BUF_MAX, ML_MODEL_PATH,
    AUTO_RESPONSE, AUTO_KILL_SCORE, RULES_DIR,
)
from server.database.storage import save_alert
from server.core.graph import get_chains
from server.threatintel import check_ioc
from server.core.dll_monitor import check_dll_hijacking, add_dll_event
from server.core.sequence_heuristics import record_event, score_frequency, score_sequence
from server.core.file_behavior import load_rules as load_file_rules, score_events as score_file_events

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _SKL = True
except ImportError:
    _SKL = False
    print("[ML] scikit-learn not installed — ML layer disabled.")

# ── ML state ──────────────────────────────────────────────────────────────────
_ml_model   = None
_ml_scaler  = None
_ml_trained = False
_ml_buf: list = []
_since_retrain = 0
_ml_lock    = threading.Lock()
_training   = False

# ── Per-system behavioral context ─────────────────────────────────────────────
_sys_history: dict = defaultdict(lambda: deque(maxlen=100))
_sys_lock = threading.Lock()
_SYS_HISTORY_MAX_SYSTEMS = 100  # Max systems to track (memory bound)

# ── Network tracking (L6) ────────────────────────────────────────────────────
_net_conns: dict = defaultdict(list)   # system_id → [{process,ip,port,ts}]
_net_lock = threading.Lock()
_NET_CONNS_MAX_PER_SYSTEM = 1000  # Max connections per system
_NET_CONNS_MAX_SYSTEMS = 100      # Max systems to track

# ── File tracking (L7) ───────────────────────────────────────────────────────
_file_events: dict = defaultdict(list)  # system_id → [{process,path,action,ts}]
_file_lock = threading.Lock()
_FILE_EVENTS_MAX_PER_SYSTEM = 5000  # Max file events per system
_FILE_EVENTS_MAX_SYSTEMS = 100       # Max systems to track

# ── YAML rule caches ─────────────────────────────────────────────────────────
_chains_rules   = []
_heuristic_w    = {}
_pc_rules       = {}
_mitre_data     = {}
_safe_data      = {}
_rules_loaded   = False
_file_rules = None

# ── Auto-response rate limit — max kills per system per minute ────────────────
# Prevents an attacker from weaponising the auto-kill by flooding spoofed events
# to repeatedly terminate legitimate processes on a target system.
_AUTO_KILL_MAX_PER_MIN = 3
_auto_kill_times: dict = defaultdict(list)   # system_id → [unix timestamps]
_auto_kill_lock  = threading.Lock()
_AUTO_KILL_MAX_SYSTEMS = 100  # Max systems to track


def _can_auto_kill(system_id: str) -> bool:
    """Return True if the per-system kill rate has not been exceeded."""
    now = time.time()
    with _auto_kill_lock:
        recent = [t for t in _auto_kill_times[system_id] if now - t < 60]
        if len(recent) >= _AUTO_KILL_MAX_PER_MIN:
            return False
        recent.append(now)
        _auto_kill_times[system_id] = recent
        
        # Memory leak protection: limit tracked systems
        if len(_auto_kill_times) > _AUTO_KILL_MAX_SYSTEMS:
            _prune_auto_kill_dict(now)
        
        return True


def _prune_auto_kill_dict(now: float):
    """Remove stale entries from _auto_kill_times to prevent unbounded growth."""
    stale = [sid for sid, times in _auto_kill_times.items()
             if not times or (now - times[-1]) > 3600]
    for sid in stale:
        del _auto_kill_times[sid]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_yaml(filename: str) -> dict:
    path = os.path.join(RULES_DIR, filename)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[RULES] Error loading {filename}: {e}")
        return {}


def load_rules():
    global _chains_rules, _heuristic_w, _pc_rules, _mitre_data, _safe_data, _rules_loaded
    if _rules_loaded:
        return
    print("[RULES] Loading detection rules...")
    # Load main chains + extended LOLBin chains together
    main_chains = _load_yaml("behaviour_chains.yaml").get("chains", [])
    lolbin_chains = _load_yaml("lolbins_extended.yaml").get("chains", [])
    _chains_rules = main_chains + lolbin_chains
    _heuristic_w  = _load_yaml("heuristic_weights.yaml").get("weights", {})
    pc            = _load_yaml("parent_child_analysis.yaml")
    _pc_rules     = {
        "suspicious":        pc.get("suspicious_pairs", []),
        "safe":              pc.get("safe_pairs", []),
        "system_exceptions": pc.get("system_user_exceptions", []),
    }
    _mitre_data   = _load_yaml("mitre_mapping.yaml")
    _safe_data    = _load_yaml("safe_processes.yaml")
    _rules_loaded = True
    print(f"[RULES] L1:{len(_chains_rules)} chains  "
          f"L3:{len(_pc_rules['suspicious'])} suspicious pairs  "
          f"L4:{len(_mitre_data.get('techniques', {}))} MITRE techniques")


def _severity(score: int) -> str:
    if score >= RISK_CRITICAL: return "CRITICAL"
    if score >= RISK_HIGH:     return "HIGH"
    if score >= RISK_MEDIUM:   return "MEDIUM"
    return "LOW"


def _make_alert(sid, proc, score, confidence, reason, technique="", ioc_hit=""):
    return {
        "system_id":  sid,
        "process":    proc,
        "risk_level": _severity(score),
        "risk_score": score,
        "confidence": confidence,
        "reason":     reason,
        "technique":  technique,
        "ioc_hit":    ioc_hit,
        "timestamp":  int(time.time()),
    }


def _emit(alert):
    """Persist evidence before notification throttling; never execute a response."""
    from server.database.storage import is_suppressed
    event = _current_event.get() or {}
    alert.update({key: event.get(key, '') for key in ('event_id', 'sha256', 'exe_path')})
    alert['pid'] = event.get('pid', 0)
    alert['create_time'] = event.get('create_time', 0)
    if not alert.get('never_suppress') and is_suppressed(alert['system_id'], alert['process'], alert['reason']):
        return False
    alert_id = save_alert(alert)
    if not alert_id:
        return False
    alert['id'] = alert_id
    collected = _persisted_alerts.get()
    if collected is not None:
        collected.append(alert)
    from server.database.incidents import correlate_alert
    correlate_alert(alert_id, alert)
    return True


def _l0a_hash_check(event: dict) -> Tuple[int, str]:
    """Fast hash-based malware detection (microseconds)"""
    sha256 = event.get("sha256", "")
    if not sha256:
        return 0, ""
    
    try:
        from server.core.hash_db import check_hash
        result = check_hash(sha256)
        
        if result:
            family = result.get("family", "Unknown")
            tags = ", ".join(result.get("tags", [])[:3])
            source = result.get("source", "")
            return 100, f"Known malware hash: {family} ({source}) Tags: {tags}"
    except Exception as e:
        # Hash DB failure should not block detection
        pass
    
    return 0, ""


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 0b — YARA Signature Detection (Pattern Matching)
# ═════════════════════════════════════════════════════════════════════════════

def _l0b_yara_scan(event: dict) -> Tuple[int, str]:
    """YARA signature-based detection (50-100ms)"""
    exe_path = event.get("exe_path", "")
    if not exe_path or not os.path.exists(exe_path):
        return 0, ""
    
    try:
        from server.core.yara_engine import scan_file, is_available
        
        if not is_available():
            return 0, ""
        
        matches = scan_file(exe_path)
        
        if matches:
            # Take highest priority match
            match = matches[0]
            rule_name = match.get("rule", "Unknown")
            description = match.get("meta", {}).get("description", "")
            tags = ", ".join(match.get("tags", [])[:3])
            
            # YARA matches are HIGH confidence but not CRITICAL
            # (could be false positive on legitimate software)
            return 90, f"YARA signature match: {rule_name} - {description or tags}"
            
    except Exception as e:
        # YARA failure should not block detection
        pass
    
    return 0, ""


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 1 — Exact Behaviour Chain Rules (YAML)
# ═════════════════════════════════════════════════════════════════════════════

def _l1_chain_rules(event: dict) -> List[dict]:
    alerts = []
    parent  = event["parent"].lower()
    child   = event["child"].lower()
    cmdline = event.get("cmdline", "").lower()
    sid     = event["system_id"]

    for rule in _chains_rules:
        matched = False
        for p in rule.get("pattern", []):
            parents  = [x.lower() for x in p.get("parent",  [])]
            children = [x.lower() for x in p.get("child",   [])]
            kws      = [x.lower() for x in p.get("cmdline_contains", [])]

            if (parents or children or kws) and (not parents or parent in parents) and (not children or child in children) and (not kws or any(k in cmdline for k in kws)):
                matched = True
                break

        if matched:
            a = _make_alert(sid, child, rule.get("score", 80), "HIGH",
                f"L1 EXACT MATCH: {rule['name']} — {rule['description']}",
                ", ".join(rule.get("mitre", [])), "")
            a["never_suppress"] = bool(rule.get("never_suppress", False))
            _emit(a)
            alerts.append(a)

    return alerts


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 2 — Heuristic Weighted Scoring (YAML)
# ═════════════════════════════════════════════════════════════════════════════

def _l2_heuristic(event: dict) -> Tuple[int, List[str]]:
    score    = 0
    reasons  = []
    cmdline  = event.get("cmdline", "").lower()
    parent   = event["parent"].lower()
    child    = event["child"].lower()
    exe_path = event.get("exe_path", "").lower()

    # ── Dev-tool cmdline exclusions ───────────────────────────────────────
    # If the cmdline looks like a typical npm/pip/build tool invocation,
    # skip L2 scoring entirely — these are ALL legitimate on dev machines.
    DEV_CMDLINE_PATTERNS = [
        "npm install", "npm run", "npm test", "npm build", "npm ci",
        "npm start", "npm publish", "npx ",
        "pip install", "pip3 install", "pip download",
        "python setup.py", "python -m pytest", "python -m pip",
        "pytest ", "tox ", "flake8 ", "black ", "mypy ",
        "cargo build", "cargo test", "cargo run",
        "dotnet build", "dotnet test", "dotnet run", "dotnet restore",
        "gradle ", "mvn ", "make ", "cmake ",
        "jest ", "vitest ", "webpack ", "vite ", "rollup ",
        "eslint ", "prettier ", "tslint ",
        "git commit", "git push", "git pull", "git fetch", "git clone",
        "git checkout", "git merge", "git rebase", "git stash",
        "docker build", "docker run", "docker-compose",
        "set-executionpolicy remotesigned",   # common VS Code setup step
        "set-executionpolicy bypass",          # common CI setup
    ]
    # A build-command substring does not make the surrounding command safe.

    for flag in _heuristic_w.get("cmdline_flags", []):
        if flag["pattern"].lower() in cmdline:
            score += flag["score"]
            reasons.append(flag["description"])

    for pair in _heuristic_w.get("parent_child_pairs", []):
        if parent in [x.lower() for x in pair["parent"]] \
                and child in [x.lower() for x in pair["child"]]:
            score += pair["score"]
            reasons.append(pair["description"])

    # Execution patterns — long_cmdline and very_long_cmdline are mutually
    # exclusive: only the HIGHER one fires to avoid double-counting.
    long_score  = 0
    long_reason = ""
    for pat in _heuristic_w.get("execution_patterns", []):
        name = pat.get("name", "")
        if name == "suspicious_path":
            if any(p.lower() in cmdline for p in pat.get("paths", [])):
                score += pat["score"]
                reasons.append(pat["description"])
        elif name == "long_cmdline":
            if len(cmdline) > pat["threshold"] and pat["score"] > long_score:
                long_score  = pat["score"]
                long_reason = f"{pat['description']} ({len(cmdline)} chars)"
        elif name == "very_long_cmdline":
            if len(cmdline) > pat["threshold"] and pat["score"] > long_score:
                long_score  = pat["score"]
                long_reason = f"{pat['description']} ({len(cmdline)} chars)"
        elif name == "orphan_process" and parent == "unknown":
            score += pat["score"]
            reasons.append(pat["description"])

    if long_score > 0:
        score   += long_score
        reasons.append(long_reason)

    # Trusted-path discount: if the executable runs from a trusted Windows
    # directory OR a known dev-tool install path, reduce score by 30%.
    trusted_paths = _safe_data.get("trusted_paths", [])
    if exe_path and any(tp.lower() in exe_path for tp in trusted_paths):
        discount = int(score * 0.30)
        if discount > 0:
            score   -= discount
            reasons.append(f"Trusted-path discount applied (-{discount})")

    return score, reasons


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 3 — Parent-Child Analysis (YAML)
# ═════════════════════════════════════════════════════════════════════════════

def _l3_parent_child(event: dict) -> Tuple[int, str]:
    parent = event["parent"].lower()
    child  = event["child"].lower()
    user   = event.get("user", "").upper()

    for pair in _pc_rules.get("safe", []):
        if parent == pair["parent"].lower() and child == pair["child"].lower():
            return 0, ""

    if user == "SYSTEM":
        for exc in _pc_rules.get("system_exceptions", []):
            exc_parents = [x.lower() for x in exc["parent"]]
            if child == exc["child"].lower() and parent in exc_parents:
                return 0, exc["description"]

    for pair in _pc_rules.get("suspicious", []):
        if parent == pair["parent"].lower() and child == pair["child"].lower():
            return pair["score"], pair["description"]

    return 0, ""


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 4 — MITRE ATT&CK Intent Classifier (YAML)
# ═════════════════════════════════════════════════════════════════════════════

def _l4_intent(cmdline: str) -> Tuple[str, int]:
    clf  = _mitre_data.get("intent_classifier", {})
    if not clf:
        return "normal_admin", 0

    total = 0
    for patterns in clf.get("keywords", {}).values():
        for item in patterns:
            if item["pattern"].lower() in cmdline.lower():
                total += item["score"]

    thresholds = clf.get("thresholds", {})
    if total >= thresholds.get("critical_malware",   90): return "critical_malware",   total
    if total >= thresholds.get("ransomware_activity",85): return "ransomware_activity", total
    if total >= thresholds.get("credential_access",  75): return "credential_access",   total
    if total >= thresholds.get("lateral_movement",   60): return "lateral_movement",    total
    if total >= thresholds.get("reconnaissance",     40): return "reconnaissance",       total
    if total >= thresholds.get("suspicious_activity",25): return "suspicious_execution", total
    return "normal_admin", 0


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 5 — ML Anomaly Detection (Isolation Forest)
# ═════════════════════════════════════════════════════════════════════════════

def _features(e: dict) -> list:
    child    = e.get("child",    "").lower()
    parent   = e.get("parent",  "").lower()
    cmdline  = e.get("cmdline", "").lower()
    exe_path = e.get("exe_path","").lower()

    try:
        hour = datetime.datetime.utcfromtimestamp(e.get("time", 0)).hour
    except Exception:
        hour = 12

    enc  = int(any(k in cmdline for k in ["-enc", "base64", "frombase64", "iex("]))
    dl   = int(any(k in cmdline for k in ["downloadstring", "webclient", "invoke-webrequest"]))
    byp  = int(any(k in cmdline for k in ["bypass", "-nop", "hidden"]))

    # Entropy: obfuscated strings have entropy > 4.5
    cmd_entropy  = _entropy(cmdline)
    # High entropy + short process name = likely injection / hollowing
    name_entropy = _entropy(child)
    # Suspicious path flag
    susp_path = int(any(p in exe_path for p in
                        ["\\appdata\\", "\\temp\\", "\\public\\", "\\programdata\\"]))
    # System process masquerading
    is_sys_name = int(child in _SYSTEM32_PROCS)
    # Trusted dir mismatch
    trusted_dir = int(any(exe_path.startswith(td) for td in _TRUSTED_DIRS))
    masquerade  = int(is_sys_name and bool(exe_path) and not trusted_dir)

    # ── New features (medium-priority improvement) ────────────────────────
    # Feature 19: parent is a LOLBin — attacker pivoting through a trusted binary
    parent_is_lolbin = float(parent in LOLBINS)

    # Feature 20: network URL present in cmdline — download or C2 indicator
    net_in_cmd = int("http://" in cmdline or "https://" in cmdline)

    # Feature 21: raw IP literal in cmdline — beacon/staging over direct IP
    ip_in_cmd = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', cmdline)))

    # Feature 22: process running as SYSTEM — elevated context raises suspicion
    # when combined with other anomalous signals
    is_system = float(e.get("user", "").upper() == "SYSTEM")

    return [
        float(child  in MALICIOUS_TOOLS),       # 0
        float(child  in LOLBINS),               # 1
        float(parent in OFFICE_APPS),           # 2
        float(parent in BROWSERS),              # 3
        float(child  in SCRIPT_ENGINES),        # 4
        float(child  in RANSOMWARE_TOOLS),      # 5
        float(child  in CREDENTIAL_TOOLS),      # 6
        float(enc), float(dl), float(byp),      # 7-9
        min(len(cmdline) / 1000.0, 1.0),        # 10 — cmdline length
        float(hour) / 23.0,                     # 11 — time of day
        float(int(e.get("pid", 0)) < 1000),     # 12 — low PID
        min(len(child) / 30.0, 1.0),            # 13 — name length
        float(parent == "unknown"),             # 14 — orphan process
        min(cmd_entropy / 6.0, 1.0),            # 15 — cmdline entropy
        min(name_entropy / 5.0, 1.0),           # 16 — process name entropy
        float(susp_path),                       # 17 — suspicious exe path
        float(masquerade),                      # 18 — system name from wrong dir
        parent_is_lolbin,                       # 19 — parent is a LOLBin
        float(net_in_cmd),                      # 20 — http/https URL in cmdline
        float(ip_in_cmd),                       # 21 — raw IP address in cmdline
        is_system,                              # 22 — running as SYSTEM
    ]


def _ml_buf_add(event):
    global _ml_buf
    if len(_ml_buf) >= ML_BUF_MAX:
        _ml_buf.pop(0)
    _ml_buf.append(event)


def _do_train(events: list):
    global _ml_model, _ml_scaler, _ml_trained, _since_retrain, _training
    if not _SKL:
        _training = False; return
    try:
        X_raw  = np.array([_features(e) for e in events])
        scaler = StandardScaler()
        X      = scaler.fit_transform(X_raw)
        model  = IsolationForest(
                                 n_estimators=200,
                                 contamination=0.02,   # 2% — tighter than default 5%
                                 max_samples="auto",
                                 random_state=42)
        model.fit(X)
        with _ml_lock:
            _ml_model = model; _ml_scaler = scaler
            _ml_trained = True; _since_retrain = 0
        print(f"[ML] Trained on {len(events)} events.")

        # ── Persist model to disk so restarts don't reset the baseline ────
        try:
            import joblib
            joblib.dump({"model": model, "scaler": scaler,
                         "n_features": len(_features(events[0]))},
                        ML_MODEL_PATH)
            print(f"[ML] Model saved → {ML_MODEL_PATH}")
        except Exception as e:
            print(f"[ML] Model save failed (non-fatal): {e}")

    except Exception as e:
        print(f"[ML ERROR] {e}")
    finally:
        _training = False


def _load_persisted_model():
    """
    Load a previously trained model from disk on server startup with validation.
    This eliminates the blind window (ML_TRAIN_AFTER events) after every restart.
    Called once from initialize().
    
    Validates:
      - File exists and is readable
      - Feature count matches current implementation
      - Model can perform inference without crashing
      - Scaler has correct shape
    """
    global _ml_model, _ml_scaler, _ml_trained
    if not _SKL:
        return
    
    try:
        import joblib, os as _os
        import numpy as np
        
        if not _os.path.exists(ML_MODEL_PATH):
            print("[ML] No persisted model found — will train after "
                  f"{ML_TRAIN_AFTER} events.")
            return
        
        # Check file size - corrupted files are often 0 bytes or truncated
        file_size = _os.path.getsize(ML_MODEL_PATH)
        if file_size < 1000:  # Model should be at least 1KB
            print(f"[ML] Persisted model file is too small ({file_size} bytes) "
                  f"— likely corrupted, will retrain.")
            try:
                _os.remove(ML_MODEL_PATH)  # Delete corrupted file
            except Exception:
                pass
            return
        
        # Load the model
        saved = joblib.load(ML_MODEL_PATH)
        
        # Validate structure
        if not isinstance(saved, dict) or "model" not in saved or "scaler" not in saved:
            print("[ML] Persisted model has invalid structure — will retrain.")
            return
        
        # Validate feature count matches current feature vector size
        # (model is stale if features were added since last save)
        dummy_event = {
            "child": "test.exe", "parent": "explorer.exe",
            "cmdline": "", "exe_path": "", "user": "",
            "pid": 1234, "time": 0,
        }
        current_n = len(_features(dummy_event))
        saved_n = saved.get("n_features", 0)
        
        if saved_n != current_n:
            print(f"[ML] Persisted model feature count mismatch "
                  f"({saved_n} saved vs {current_n} current) "
                  f"— will retrain.")
            return
        
        model = saved["model"]
        scaler = saved["scaler"]
        
        # Validate scaler shape
        if hasattr(scaler, 'n_features_in_') and scaler.n_features_in_ != current_n:
            print(f"[ML] Scaler feature count mismatch "
                  f"({scaler.n_features_in_} vs {current_n}) — will retrain.")
            return
        
        # Test inference with dummy data
        try:
            test_features = _features(dummy_event)
            test_scaled = scaler.transform(np.array([test_features]))
            test_pred = model.predict(test_scaled)
            test_score = model.decision_function(test_scaled)
            
            # Validate outputs are sane
            if not isinstance(test_pred, np.ndarray) or len(test_pred) != 1:
                raise ValueError("Model prediction shape invalid")
            if not isinstance(test_score, np.ndarray) or len(test_score) != 1:
                raise ValueError("Model score shape invalid")
            if not np.isfinite(test_score[0]):
                raise ValueError("Model score is not finite")
                
        except Exception as e:
            print(f"[ML] Model inference test failed: {e} — will retrain.")
            return
        
        # All validation passed - load the model
        with _ml_lock:
            _ml_model   = model
            _ml_scaler  = scaler
            _ml_trained = True
        
        print(f"[ML] ✅ Loaded and validated persisted model from {ML_MODEL_PATH}")
        print(f"[ML]    Features: {current_n}, File size: {file_size:,} bytes")
        
    except EOFError:
        print("[ML] Model file is corrupted (EOFError) — will retrain.")
        try:
            _os.remove(ML_MODEL_PATH)
        except Exception:
            pass
    except Exception as e:
        print(f"[ML] Could not load persisted model (non-fatal): {e}")
        print("[ML] Will train a new model after receiving events.")


def _maybe_train():
    global _training
    if _training or not _SKL:
        return
    n = len(_ml_buf)
    if not _ml_trained and n >= ML_TRAIN_AFTER:
        _training = True
        threading.Thread(target=_do_train, args=(_ml_buf[:],), daemon=True).start()
    elif _ml_trained and _since_retrain >= ML_RETRAIN_EVERY:
        _training = True
        threading.Thread(target=_do_train, args=(_ml_buf[-ML_BUF_MAX:],), daemon=True).start()


def _l5_ml(event: dict, base_score: int) -> Tuple[int, str]:
    global _ml_model, _ml_scaler, _ml_trained
    if not EXPERIMENTAL_ML:
        return 0, ""
    # Run ML as long as the event hasn't already been confirmed HIGH/CRITICAL by
    # rule-based layers. Allowing ML to run up to RISK_HIGH lets it corroborate
    # moderate-score events and catch novel patterns the rules don't cover.
    # (Old threshold was base_score >= 20, which blocked ML on almost everything.)
    if base_score >= RISK_HIGH or not _SKL:
        return 0, ""
    with _ml_lock:
        model, scaler, trained = _ml_model, _ml_scaler, _ml_trained
    if not trained or model is None:
        return 0, ""
    try:
        feat_vec = _features(event)
        # If the scaler was trained on a different feature count (e.g. from a
        # previous server run before features were added), discard the stale
        # model and retrain rather than crashing with a shape mismatch.
        if hasattr(scaler, 'n_features_in_') and scaler.n_features_in_ != len(feat_vec):
            with _ml_lock:
                _ml_model   = None
                _ml_scaler  = None
                _ml_trained = False
            print(f"[ML] Feature count changed ({scaler.n_features_in_} → "
                  f"{len(feat_vec)}) — model reset, will retrain.")
            return 0, ""
        feat = scaler.transform(np.array([feat_vec]))
        pred = model.predict(feat)[0]
        raw  = model.decision_function(feat)[0]
        ml_score = int(max(0, min(79, (0.3 - raw) * 100)))
        if pred == -1 and ml_score >= 40:
            return ml_score, f"ML anomaly (score {ml_score})"
    except Exception:
        pass
    return 0, ""


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 6 — Network Behaviour Analysis
# ═════════════════════════════════════════════════════════════════════════════

def add_network_event(system_id: str, process: str, dest_ip: str,
                      dest_port: int, is_internal: bool = False):
    with _net_lock:
        _net_conns[system_id].append(
            {"process":  process,
             "ip":       dest_ip,
             "port":     dest_port,
             "internal": is_internal,
             "ts":       time.time()})
        
        # Per-system cap (already exists)
        if len(_net_conns[system_id]) > _NET_CONNS_MAX_PER_SYSTEM:
            _net_conns[system_id] = _net_conns[system_id][-_NET_CONNS_MAX_PER_SYSTEM:]
        
        # Global cap: prevent unbounded growth from 100s of systems
        if len(_net_conns) > _NET_CONNS_MAX_SYSTEMS:
            _prune_network_tracking()


def _prune_network_tracking():
    """
    Remove stale or oldest systems from network tracking to prevent memory leaks.
    Keeps most recently active systems.
    Called with _net_lock already held.
    """
    now = time.time()
    
    # First pass: Remove systems with no recent activity (1 hour)
    stale = [sid for sid, conns in _net_conns.items()
             if not conns or (now - conns[-1]["ts"]) > 3600]
    for sid in stale:
        del _net_conns[sid]
    
    # Second pass: If still over limit, remove oldest systems
    if len(_net_conns) > _NET_CONNS_MAX_SYSTEMS:
        # Sort by most recent activity
        systems_by_time = sorted(_net_conns.items(),
                                key=lambda x: x[1][-1]["ts"] if x[1] else 0,
                                reverse=True)
        # Keep only the most recent MAX_SYSTEMS
        to_keep = {sid for sid, _ in systems_by_time[:_NET_CONNS_MAX_SYSTEMS]}
        to_remove = [sid for sid in _net_conns.keys() if sid not in to_keep]
        for sid in to_remove:
            del _net_conns[sid]


def _l6_network(system_id: str, process: str) -> Tuple[int, List[str]]:
    score, reasons = 0, []
    with _net_lock:
        conns = _net_conns.get(system_id, [])
    now    = time.time()
    recent = [c for c in conns if c["process"] == process and now - c["ts"] < 300]
    if len(recent) < 3:
        return 0, []

    # ── C2 Beaconing: regular periodic connections to EXTERNAL IPs ────────
    # Internal IPs are excluded — beaconing detection only makes sense for
    # outbound C2 traffic, not legitimate internal server polling.
    external = [c for c in recent if not c.get("internal", False)]
    if len(external) >= 5:
        ts_list   = sorted(c["ts"] for c in external)
        intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list)-1)]
        avg       = sum(intervals) / len(intervals)
        variance  = sum((x - avg)**2 for x in intervals) / len(intervals)
        if variance < 10 and avg < 60:
            score += 70
            reasons.append(f"C2 beaconing pattern ({avg:.1f}s avg interval, "
                           f"external IPs only)")

    # ── Lateral movement: connections to internal hosts on suspicious ports ─
    # This is the fix for the blind spot: lateral movement is 100% internal
    # by definition (SMB 445, RDP 3389, WinRM 5985/5986, DCOM 135/139).
    lateral_ports = {445, 3389, 135, 139, 5985, 5986}
    lateral_hits  = [c for c in recent if c["port"] in lateral_ports]
    if lateral_hits:
        port = lateral_hits[0]["port"]
        internal_tag = " (internal)" if lateral_hits[0].get("internal") else ""
        score += 80
        reasons.append(f"Lateral movement port: {port}{internal_tag}")

    # ── Unique external IP spread (scanning/exfil indicator) ──────────────
    unique_ext_ips = {c["ip"] for c in recent if not c.get("internal", False)}
    if len(unique_ext_ips) > 10:
        score += 30
        reasons.append(f"Multiple external IPs contacted: {len(unique_ext_ips)}")

    return score, reasons


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 7 — File & Registry Behaviour Analysis
# ═════════════════════════════════════════════════════════════════════════════

def add_file_event(system_id: str, process: str, file_path: str, action: str):
    with _file_lock:
        _file_events[system_id].append(
            {"process": process, "path": file_path, "action": action, "ts": time.time()})
        
        # Per-system cap (already exists)
        if len(_file_events[system_id]) > _FILE_EVENTS_MAX_PER_SYSTEM:
            _file_events[system_id] = _file_events[system_id][-_FILE_EVENTS_MAX_PER_SYSTEM:]
        
        # Global cap: prevent unbounded growth
        if len(_file_events) > _FILE_EVENTS_MAX_SYSTEMS:
            _prune_file_tracking()


def _prune_file_tracking():
    """
    Remove stale or oldest systems from file event tracking to prevent memory leaks.
    Called with _file_lock already held.
    """
    now = time.time()
    
    # First pass: Remove systems with no recent activity (1 hour)
    stale = [sid for sid, events in _file_events.items()
             if not events or (now - events[-1]["ts"]) > 3600]
    for sid in stale:
        del _file_events[sid]
    
    # Second pass: If still over limit, remove oldest systems
    if len(_file_events) > _FILE_EVENTS_MAX_SYSTEMS:
        # Sort by most recent activity
        systems_by_time = sorted(_file_events.items(),
                                key=lambda x: x[1][-1]["ts"] if x[1] else 0,
                                reverse=True)
        # Keep only the most recent MAX_SYSTEMS
        to_keep = {sid for sid, _ in systems_by_time[:_FILE_EVENTS_MAX_SYSTEMS]}
        to_remove = [sid for sid in _file_events.keys() if sid not in to_keep]
        for sid in to_remove:
            del _file_events[sid]


def _l7_file(system_id: str, process: str) -> Tuple[int, List[str]]:
    global _file_rules
    if _file_rules is None:
        _file_rules = load_file_rules(os.path.join(RULES_DIR, "file_behavior.json"))
    with _file_lock:
        fevents = list(_file_events.get(system_id, []))
    now = time.time()
    recent = [event for event in fevents if event["process"] == process
              and 0 <= now - event["ts"] < _file_rules["window_seconds"]]
    return score_file_events(recent, _file_rules)


# ═════════════════════════════════════════════════════════════════════════════
# LAYER 8 — Process Masquerading Detection (T1036.005)
# Detects system process names running from non-System32 paths
# ═════════════════════════════════════════════════════════════════════════════

# Processes that MUST run from System32 / SysWOW64
_SYSTEM32_PROCS = {
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "services.exe", "winlogon.exe", "smss.exe", "lsm.exe",
    "taskhost.exe", "taskhostw.exe", "spoolsv.exe", "dwm.exe",
}
_TRUSTED_DIRS = {
    "c:\\windows\\system32", "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
}


def _l8_masquerading(event: dict) -> List[dict]:
    """Detect a known-system process running from a non-trusted path."""
    child    = event.get("child",    "").lower().strip()
    exe_path = event.get("exe_path", "").lower().replace("/", "\\")
    sid      = event["system_id"]

    if child not in _SYSTEM32_PROCS:
        return []
    if not exe_path:
        return []   # no path info — skip

    # Allow if path starts with a trusted directory
    if any(exe_path.startswith(td) for td in _TRUSTED_DIRS):
        return []

    a = _make_alert(
        sid, child, 95, "HIGH",
        f"MASQUERADING: '{child}' running from '{exe_path}' — expected System32",
        "T1036.005",
    )
    _emit(a)
    return [a]


# ── Cmdline entropy helper ────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string. Obfuscated payloads score ~5.5-6.0."""
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def _analyze(event: dict) -> List[dict]:
    global _since_retrain
    if not _rules_loaded:
        load_rules()

    alerts  = []
    sid     = event["system_id"]
    parent  = event.get("parent", "unknown").lower()
    child   = event.get("child",  "unknown").lower()
    cmdline = event.get("cmdline", "")
    sha256  = event.get("sha256", "")

    # ── LAYER 0a: Hash-Based Signature Detection ─────────────────────────
    try:
        from server.core.hash_db import check_hash
        hash_result = check_hash(sha256)
        if hash_result:
            family = hash_result.get("family", "Unknown")
            tags = ", ".join(hash_result.get("tags", [])[:3])
            source = hash_result.get("source", "")
            a = _make_alert(sid, child, 100, "HIGH",
                f"L0a KNOWN MALWARE HASH: {family} ({source}) Tags: {tags}",
                "T1204.002", sha256)
            _emit(a); alerts.append(a)
            return alerts  # Definitive malware - no need for further analysis
    except Exception:
        pass  # Hash DB failure should not block detection
    
    # Remote executable paths must never be scanned on the server.
    # ── LAYER 0c: Threat Intel IOC matching (instant CRITICAL) ─────────────
    # Check local IOC feed first (fast)
    ioc_hits = check_ioc(
        sha256=sha256,
        name=child,
        ip=event.get("source_ip", ""),
    )
    
    # Check enhanced threat feeds (Priority 2)
    try:
        from server.core import threat_intel_enhanced
        enhanced_hits = threat_intel_enhanced.check_enhanced(
            hash_val=sha256,
            domain=event.get("domain", ""),
        )
        # Merge enhanced hits
        for hit in enhanced_hits:
            ioc_hits.append({
                "ioc_type": hit["ioc_type"],
                "ioc_value": hit["ioc_value"],
                "label": f"[{hit['feed']}] {hit['label']}",
                "severity": hit["severity"],
                "source": hit["feed"],
            })
    except Exception:
        pass  # Degrade gracefully
    
    for hit in ioc_hits:
        ioc_label = f"{hit['ioc_type']}:{hit['ioc_value']} — {hit['label']}"
        a = _make_alert(sid, child,
            95 if hit["severity"] == "CRITICAL" else 80,
            "HIGH",
            f"THREAT INTEL MATCH: {hit['label']} [{hit['source']}]",
            "IOC", ioc_label)
        _emit(a); alerts.append(a)
    if alerts:   # IOC hit is definitive — no need to run other layers
        return alerts

    # ── LAYER 8: Masquerading — runs before whitelist ──────────────────────
    masq = _l8_masquerading(event)
    if masq:
        return masq

    # ML / context bookkeeping
    _ml_buf_add(event)
    _since_retrain += 1
    if EXPERIMENTAL_ML:
        _maybe_train()
    with _sys_lock:
        _sys_history[sid].append(child)

    # ── Sequence ML: record before detection ──────────────────────────────
    record_event(sid, parent, child, cmdline)
    
    # ── Record events for advanced ML layers ──────────────────────────────
    try:
        if not EXPERIMENTAL_ML:
            raise ImportError("Experimental models disabled")
        from server.core import deep_sequence, graph_ml, baseline_autoencoder
        deep_sequence.record_sequence_event(event)
        graph_ml.record_graph_event(event)
        baseline_autoencoder.record_baseline_event(event)
    except Exception:
        pass  # Gracefully degrade if advanced ML not available

    # ── L1: Exact chain rules ──────────────────────────────────────────────
    l1_alerts = _l1_chain_rules(event)
    alerts.extend(l1_alerts)

    # When L1 fires with HIGH confidence it means we have an exact rule match.
    # Running L2 heuristics and L4 intent classifier on the same event would
    # generate 2–4 additional alerts for the same cmdline/parent-child pair,
    # flooding the incident queue with duplicates (e.g. office→powershell -enc
    # fires L1 at score 97, L2 at ~75, L3 at 40, L4 at ~80 — all for one event).
    # L6/L7/L9/L10 still run because they add DIFFERENT signal dimensions
    # (network beaconing, file ransomware activity, DLL hijacking, sequences)
    # that L1 exact-match rules cannot see.
    l1_confirmed = bool(l1_alerts)

    # Confirmed critical pairs fire immediately, skip other layers
    if (parent, child) in CRITICAL_PAIRS and not l1_alerts:
        a = _make_alert(sid, child, 95, "HIGH",
            f"CONFIRMED MALICIOUS: '{parent}' spawned '{child}' (office/browser exploit)",
            "T1566.001 / T1059")
        _emit(a); alerts.append(a)
        return alerts

    # ── L2+L3 combined score — skipped when L1 already fired ─────────────
    # This prevents duplicate heuristic alerts for the same event that L1
    # already caught with certainty.
    combined   = 0
    l2_reasons = []
    if not l1_confirmed:
        l2_score, l2_reasons = _l2_heuristic(event)
        l3_score, l3_reason  = _l3_parent_child(event)
        if l3_score > 0 and l3_reason:
            l2_reasons.append(f"L3: {l3_reason}")
        combined = l2_score + l3_score

    # ── L4: Intent classifier — skipped when L1 already fired ────────────
    # L1 exact rules already cover cmdlines that score high in L4 (e.g.
    # "vssadmin delete shadows" fires the L1 Shadow Copy rule AND would add
    # +85 from L4 intent scoring). Running L4 after L1 only adds duplicate noise.
    intent       = "normal_admin"
    intent_score = 0
    if not l1_confirmed:
        intent, intent_score = _l4_intent(cmdline)
        if intent_score > 25:
            boost = min(intent_score // 3, 30)
            combined += boost
            l2_reasons.append(f"L4: intent='{intent}' (score {intent_score})")

    # ── L6: Network ──────────────────────────────────────────────────────
    # L6/L7 run even when L1 fired — they add orthogonal signal dimensions
    # (active network beaconing, mass file encryption) that rule-matches can't see.
    l6_score, l6_reasons = _l6_network(sid, child)
    if not l1_confirmed:
        combined += l6_score
        l2_reasons.extend(f"L6: {r}" for r in l6_reasons)
    elif l6_score >= RISK_MEDIUM:
        # L1 already fired — emit L6 as its OWN alert, not a heuristic combo
        a = _make_alert(sid, child, min(l6_score, 84), "HIGH",
            "NETWORK: " + "; ".join(l6_reasons), "T1071")
        _emit(a); alerts.append(a)

    # ── L7: File ─────────────────────────────────────────────────────────
    l7_score, l7_reasons = _l7_file(sid, child)
    if not l1_confirmed:
        combined += l7_score
        l2_reasons.extend(f"L7: {r}" for r in l7_reasons)
    elif l7_score >= RISK_MEDIUM:
        a = _make_alert(sid, child, min(l7_score, 95), "HIGH",
            "FILE ACTIVITY: " + "; ".join(l7_reasons), "T1486")
        _emit(a); alerts.append(a)

    # ── Entropy boost: obfuscated cmdline raises score ────────────────────
    # Only applied when L1 did NOT fire — entropy signals are already captured
    # by L1 exact rules that match encoded/obfuscated cmdline patterns.
    if not l1_confirmed:
        cmd_ent = _entropy(cmdline)
        if cmd_ent > 5.2 and child in SCRIPT_ENGINES and combined > 0:
            boost = min(int((cmd_ent - 5.2) * 25), 20)   # cap boost at 20
            combined += boost
            l2_reasons.append(f"High cmdline entropy: {cmd_ent:.2f} (obfuscation indicator)")

    # ── L2/L3/L4 combined alert — hard cap at 84 (never CRITICAL from heuristics alone)
    # Rationale: heuristics are probabilistic signals. CRITICAL (>=85) requires
    # either an L1 exact rule match, L0 IOC hit, or L8 masquerading detection
    # — all of which have high certainty. Heuristics alone, no matter how many
    # signals stack, cap at HIGH (61-84) to prevent false CRITICAL alerts.
    if combined >= RISK_MEDIUM and l2_reasons and not l1_confirmed:
        technique = ""
        if intent == "credential_access":                 technique = "T1003"
        elif intent == "ransomware_activity":             technique = "T1490, T1486"
        elif intent == "lateral_movement":                technique = "T1021"
        elif "entropy" in " ".join(l2_reasons).lower():  technique = "T1027"
        elif "encoded" in " ".join(l2_reasons).lower():  technique = "T1027, T1059.001"

        capped_score = min(combined, 84)   # hard cap — heuristics never reach CRITICAL
        conf = "HIGH" if capped_score >= RISK_HIGH else "MEDIUM"
        a = _make_alert(sid, child, capped_score, conf,
            "HEURISTIC: " + "; ".join(l2_reasons[:6]), technique)
        _emit(a); alerts.append(a)

    # ── L5: ML fallback ───────────────────────────────────────────────────
    # ML runs only when no higher-confidence layer has already confirmed the
    # event as malicious. If L1 fired, the event is already classified with
    # certainty — ML adding a second lower-confidence alert adds noise, not value.
    if not l1_confirmed:
        ml_score, ml_reason = _l5_ml(event, combined)
        if ml_score > 0 and not any(a["process"] == child for a in alerts):
            a = _make_alert(sid, child, ml_score, "MEDIUM",
                f"ML ANOMALY: {ml_reason}", "T1059")
            _emit(a); alerts.append(a)

    # ── LAYER 9: DLL Hijacking detection ──────────────────────────────────
    # DLL hijacking is orthogonal to process spawning — a process can be clean
    # from L1's perspective but load a hijacked DLL, or vice-versa.
    # Always run regardless of l1_confirmed. Use a separate alert so it doesn't
    # get folded into the heuristic alert (different technique, different action).
    dll_score, dll_reasons = check_dll_hijacking(sid, child, event.get("exe_path", ""))
    if dll_score > 0:
        # Only emit if we don't already have a higher-scoring DLL alert for
        # this process in this analysis pass (prevents double-emit on retry)
        existing_dll = any(
            a["process"] == child and "DLL" in a.get("reason", "")
            for a in alerts
        )
        if not existing_dll:
            a = _make_alert(sid, child, dll_score, "HIGH",
                "DLL HIJACK: " + "; ".join(dll_reasons), "T1574.001")
            _emit(a); alerts.append(a)

    # ── LAYER 10: Sequence ML ──────────────────────────────────────────────
    # Skip when:
    #   a) L1 already confirmed a high-confidence rule match (sequence adds noise)
    #   b) Any alert >= RISK_HIGH already fired (event is already well-classified)
    already_high = any(a["risk_score"] >= RISK_HIGH for a in alerts)
    if not l1_confirmed and not already_high:
        freq_score, freq_reason = score_frequency(sid, parent, child)
        seq_score,  seq_reason  = score_sequence(sid, parent, child)

        seq_combined = freq_score + seq_score
        seq_reasons  = [r for r in [freq_reason, seq_reason] if r]

        if seq_combined >= RISK_MEDIUM and seq_reasons:
            seq_technique = "T1059"
            combined_reason = " ".join(seq_reasons).upper()
            if "PERSISTENCE AFTER SHELL" in combined_reason:
                if "schtasks" in child:   seq_technique = "T1053.005"
                elif "reg.exe" in child:  seq_technique = "T1547.001"
                elif "sc.exe" in child:   seq_technique = "T1543.003"
                else:                     seq_technique = "T1547"
            elif "RECON BURST" in combined_reason:
                seq_technique = "T1082, T1069"
            elif "DOWNLOAD-EXECUTE" in combined_reason:
                seq_technique = "T1105, T1059"
            elif "CREDENTIAL ACCESS CHAIN" in combined_reason:
                seq_technique = "T1003"
            elif "PROCESS STORM" in combined_reason:
                seq_technique = "T1055"

            # Cap sequence score at 75 — sequence patterns are probabilistic,
            # never certain enough to reach CRITICAL on their own.
            a = _make_alert(sid, child, min(seq_combined, 75), "MEDIUM",
                "SEQUENCE: " + " | ".join(seq_reasons), seq_technique)
            _emit(a); alerts.append(a)

    # ── LAYER 11: Deep Sequence LSTM ───────────────────────────────────────
    # Advanced BiLSTM with attention — learns normal process execution sequences
    # per endpoint and detects deviation. Only run when not already confirmed.
    if not l1_confirmed and not already_high:
        try:
            if not EXPERIMENTAL_ML:
                raise ImportError("Experimental models disabled")
            from server.core.deep_sequence import detect_sequence_anomaly, is_available
            if is_available():
                lstm_score, lstm_reason = detect_sequence_anomaly(sid, event)
                if lstm_score >= RISK_MEDIUM:
                    a = _make_alert(sid, child, min(lstm_score, 85), "HIGH",
                        f"DEEP SEQUENCE: {lstm_reason}", "T1059")
                    _emit(a); alerts.append(a)
        except Exception as e:
            pass  # Degrade gracefully
    
    # ── LAYER 12: Graph Neural Network ─────────────────────────────────────
    # GNN analyzes entire process tree structure — detects APT campaign patterns,
    # reconnaissance→exploitation chains, lateral movement topology.
    # Only runs when event is part of a multi-hop chain.
    if not l1_confirmed and not already_high:
        try:
            if not EXPERIMENTAL_ML:
                raise ImportError("Experimental models disabled")
            from server.core.graph_ml import detect_graph_anomaly, is_available
            from server.core.graph import _graphs
            if is_available():
                # Get recent events for this system to build graph
                with _sys_lock:
                    sys_events = [e for e in _ml_buf if e.get("system_id") == sid][-50:]
                if len(sys_events) >= 5:
                    gnn_score, gnn_reason = detect_graph_anomaly(sid, sys_events)
                    if gnn_score >= RISK_MEDIUM:
                        a = _make_alert(sid, child, min(gnn_score, 88), "HIGH",
                            f"GRAPH ATTACK: {gnn_reason}", "T1204")
                        _emit(a); alerts.append(a)
        except Exception as e:
            pass  # Degrade gracefully
    
    # ── LAYER 13: Behavioral Baseline Anomaly ──────────────────────────────
    # Per-endpoint autoencoder — detects when this specific endpoint does
    # something unusual (e.g. accountant PC suddenly runs mimikatz, dev machine
    # accesses financial data). This is the HIGHEST ACCURACY layer for
    # reducing false positives.
    if not l1_confirmed:
        try:
            if not EXPERIMENTAL_ML:
                raise ImportError("Experimental models disabled")
            from server.core.baseline_autoencoder import detect_baseline_anomaly, is_available
            if is_available():
                baseline_score, baseline_reason = detect_baseline_anomaly(sid, event)
                if baseline_score >= RISK_MEDIUM:
                    # High confidence — baseline is trained on this specific endpoint
                    conf = "HIGH" if baseline_score >= RISK_HIGH else "MEDIUM"
                    a = _make_alert(sid, child, min(baseline_score, 88), conf,
                        f"BASELINE: {baseline_reason}", "T1078")
                    _emit(a); alerts.append(a)
        except Exception as e:
            pass  # Degrade gracefully

    # ── Graph-based chain detection ────────────────────────────────────────
    # Guards:
    #   1. Skip if L1 already confirmed this event — chain adds nothing new.
    #   2. Only score chains containing at least one known-suspicious process
    #      (prevents benign dev-tool chains: code→node→cmd→npm firing).
    #   3. Deduplicate: only emit a chain alert if we haven't already emitted
    #      one for this exact chain tail on this system in this analysis pass.
    if not l1_confirmed:
        SUSPECT_CHAIN_NODES = (
            LOLBINS | SCRIPT_ENGINES | MALICIOUS_TOOLS
            | RANSOMWARE_TOOLS | CREDENTIAL_TOOLS
        )
        seen_chain_tails: set = set()
        for chain in get_chains(sid, min_len=4):
            if not any(node in SUSPECT_CHAIN_NODES for node in chain):
                continue   # all-benign chain — skip
            tail = chain[-1]
            if tail in seen_chain_tails:
                continue   # already emitted a chain alert for this tail
            seen_chain_tails.add(tail)
            # Don't re-emit if this process already has a higher-scoring alert
            if any(a["process"] == tail and a["risk_score"] >= RISK_HIGH
                   for a in alerts):
                continue
            chain_score = min(55 + len(chain) * 8, 75)   # cap at 75, not 84
            a = _make_alert(sid, tail, chain_score, "MEDIUM",
                f"ATTACK CHAIN ({len(chain)} hops): {' → '.join(chain)}",
                "T1059")
            _emit(a); alerts.append(a)
    
    # ── Priority 2: Track attack chains & generate predictions ────────────
    try:
        from server.core import predictive_scoring
        for alert in alerts:
            # Classify stage and record in kill chain tracker
            stage = predictive_scoring.classify_stage(event, alert)
            if stage:
                predictive_scoring.record_stage(sid, stage, event, alert)
    except Exception:
        pass  # Degrade gracefully
    
    # ── Priority 2: Generate explanations for alerts ──────────────────────
    # Build score breakdown for explainable AI
    if alerts:
        try:
            from server.core import explainable_ai
            
            # Build scores dict for explanation
            scores = {}
            if l1_alerts:
                scores["L1_Exact"] = (max(a["risk_score"] for a in l1_alerts), 
                                     [a["reason"] for a in l1_alerts])
            if combined > 0 and not l1_confirmed:
                scores["L2_Heuristic"] = (combined, l2_reasons)
            if l6_score > 0:
                scores["L6_Network"] = (l6_score, l6_reasons)
            if l7_score > 0:
                scores["L7_File"] = (l7_score, l7_reasons)
            
            # Record for pattern matching
            for alert in alerts:
                explainable_ai.record_alert(alert, event)
        except Exception:
            pass  # Degrade gracefully

    return alerts


def initialize():
    global _file_rules
    _file_rules = load_file_rules(os.path.join(RULES_DIR, "file_behavior.json"))
    load_rules()
    if EXPERIMENTAL_ML:
        _load_persisted_model()


def analyze(event):
    collected = []
    event_token = _current_event.set(event)
    alert_token = _persisted_alerts.set(collected)
    try:
        _analyze(event)
        return collected
    finally:
        _current_event.reset(event_token)
        _persisted_alerts.reset(alert_token)


def handle_etw_event(event: dict):
    """
    Route an ETW event to the appropriate detection handler.
    Called from the /etw_events API endpoint for every event the agent sends.

    Each event type feeds a specific detection layer:

      etw_process_create  → runs through the full 10-layer analyze() pipeline
                            using kernel-provided cmdline/path (more reliable
                            than psutil which can miss short-lived processes)
      etw_thread_inject   → immediate CRITICAL alert (T1055 process injection)
      etw_image_load      → L9 DLL hijacking check
      etw_network_connect → L6 beaconing + lateral movement
      etw_registry_write  → registry abuse rules (persistence, defence evasion)
      etw_dns_query       → L0 IOC check against domain feed
      etw_scriptblock     → L1/L2/L4 rules applied to decoded PS content
    """
    etype     = event.get("event", "")
    system_id = event.get("system_id", "")
    if not system_id:
        return

    # ── Process create — run the full detection pipeline ──────────────────
    if etype == "etw_process_create":
        # Build a normalised event compatible with analyze()
        # ETW gives us the real kernel cmdline — more trustworthy than
        # psutil which reads from the process PEB (can be tampered).
        synthetic = {
            "system_id": system_id,
            "event":     "process_spawn",
            "parent":    event.get("parent_proc", "unknown"),
            "child":     event.get("process",     "unknown"),
            "pid":       event.get("pid",         0),
            "time":      event.get("time",        int(time.time())),
            "cmdline":   event.get("cmdline",     ""),
            "exe_path":  event.get("image_path",  ""),
            "user":      event.get("user",        ""),
            "sha256":    "",   # ETW process create doesn't carry hash
            # Mark source so downstream can log/display it
            "source":    "etw",
        }
        # Enrich parent name from our pid→name cache in the event payload
        ppid = event.get("ppid", 0)
        if ppid:
            synthetic["parent_pid"] = ppid

        from server.core.graph import add_event as graph_add
        from server.database.storage import save_event
        save_event(synthetic)
        graph_add(synthetic)
        analyze(synthetic)

    # ── Thread injection — immediate CRITICAL alert ───────────────────────
    elif etype == "etw_thread_inject":
        source_proc = event.get("source_proc", "unknown")
        target_proc = event.get("target_proc", "unknown")
        source_pid  = event.get("source_pid",  0)
        target_pid  = event.get("target_pid",  0)

        # Skip obvious false positives: debuggers injecting into child,
        # and the System/Idle process.
        fp_pairs = {
            ("devenv.exe", ""),       # VS debugger
            ("msvsmon.exe", ""),      # VS remote debugger
            ("vsdebugger.exe", ""),
        }
        if any(fp in source_proc.lower() for fp, _ in fp_pairs):
            return

        alert = _make_alert(
            sid=system_id,
            proc=f"{source_proc} → {target_proc}",
            score=95,
            confidence="HIGH",
            reason=(f"ETW: Remote thread created by PID {source_pid} "
                    f"({source_proc}) into PID {target_pid} ({target_proc}) "
                    f"— process injection (T1055)"),
            technique="T1055",
        )
        _emit(alert)

    # ── Image load — feed L9 DLL hijacking ───────────────────────────────
    elif etype == "etw_image_load":
        process  = event.get("process",    "unknown")
        dll_path = event.get("image_path", "")
        signed   = bool(event.get("signed", True))
        if dll_path.lower().endswith(".dll"):
            add_dll_event(
                system_id=system_id,
                process=process,
                dll_name=os.path.basename(dll_path),
                dll_path=dll_path,
                signed=signed,
            )

    # ── Network connect — feed L6 ─────────────────────────────────────────
    elif etype == "etw_network_connect":
        process  = event.get("process",     "unknown")
        dest_ip  = event.get("remote_ip",   "")
        dest_port = int(event.get("remote_port", 0))
        if dest_ip and dest_port:
            # Determine if private IP for lateral movement routing
            try:
                parts = list(map(int, dest_ip.split(".")))
                is_internal = (
                    parts[0] == 10 or
                    (parts[0] == 172 and 16 <= parts[1] <= 31) or
                    (parts[0] == 192 and parts[1] == 168)
                )
            except Exception:
                is_internal = False
            add_network_event(system_id, process, dest_ip, dest_port, is_internal)

    # ── Registry write — rule-based analysis ─────────────────────────────
    elif etype == "etw_registry_write":
        _handle_etw_registry(system_id, event)

    # ── DNS query — L0 IOC domain check ──────────────────────────────────
    elif etype == "etw_dns_query":
        process = event.get("process", "unknown")
        domain  = event.get("query",   "")
        if not domain:
            return
        hits = check_ioc(domain=domain)
        if hits:
            h = hits[0]
            alert = _make_alert(
                sid=system_id,
                proc=process,
                score=90,
                confidence="HIGH",
                reason=(f"ETW DNS: {process} queried IOC domain '{domain}' "
                        f"— {h['label']}"),
                technique="T1071.004",
                ioc_hit=f"{h['ioc_type']}:{domain}",
            )
            _emit(alert)

    # ── ScriptBlock — feed decoded PS content through L1/L2/L4 ───────────
    elif etype == "etw_scriptblock":
        _handle_etw_scriptblock(system_id, event)

    # ── Scheduled task created / modified ─────────────────────────────────
    elif etype == "etw_task_create":
        process      = event.get("process",      "taskschd.exe")
        task_name    = event.get("task_name",    "")
        task_content = event.get("task_content", "").lower()
        user         = event.get("user",         "")
        eid          = event.get("eid",          0)

        # Score based on content — tasks containing scripts are high risk
        suspicious_content = any(k in task_content for k in [
            "powershell", "cmd.exe", "wscript", "cscript", "mshta",
            "rundll32", "regsvr32", "certutil", "bitsadmin",
            "downloadstring", "iex(", "encodedcommand",
        ])
        score = 82 if suspicious_content else 65
        verb  = "modified" if eid == 4702 else "created"
        alert = _make_alert(
            sid=system_id,
            proc=process,
            score=score,
            confidence="HIGH" if suspicious_content else "MEDIUM",
            reason=(f"ETW: Scheduled task {verb} — '{task_name}'"
                    + (" (contains script engine)" if suspicious_content else "")),
            technique="T1053.005",
        )
        _emit(alert)

    # ── New service installed ──────────────────────────────────────────────
    elif etype == "etw_service_install":
        process  = event.get("process",      "services.exe")
        svc_name = event.get("service_name", "")
        svc_file = event.get("service_file", "").lower()

        # Services pointing at suspicious paths or script engines are high risk
        suspicious_svc = any(k in svc_file for k in [
            "\\temp\\", "\\appdata\\", "\\public\\", "\\programdata\\",
            "powershell", "cmd.exe", "wscript", "rundll32",
        ])
        score = 85 if suspicious_svc else 65
        alert = _make_alert(
            sid=system_id,
            proc=process,
            score=score,
            confidence="HIGH" if suspicious_svc else "MEDIUM",
            reason=(f"ETW: New service installed — '{svc_name}' → {svc_file}"
                    + (" (suspicious path)" if suspicious_svc else "")),
            technique="T1543.003",
        )
        _emit(alert)

    # ── Account / group change ─────────────────────────────────────────────
    elif etype == "etw_account_change":
        process = event.get("process",     "lsass.exe")
        target  = event.get("target_user", "")
        actor   = event.get("actor",       "")
        group   = event.get("group",       "")
        eid     = event.get("eid",         0)

        # 4720=account created, 4732/4728=added to privileged group
        if eid == 4720:
            reason = f"ETW: New user account created — '{target}' by '{actor}'"
            technique = "T1136.001"
            score = 65
        else:
            reason = (f"ETW: User '{target}' added to privileged group "
                      f"'{group}' by '{actor}'")
            technique = "T1098"
            score = 72

        alert = _make_alert(
            sid=system_id, proc=process, score=score,
            confidence="MEDIUM", reason=reason, technique=technique,
        )
        _emit(alert)


# ── Registry abuse rule engine (ETW) ─────────────────────────────────────────

# Maps monitored registry path fragment → (description, MITRE technique, score)
_REGISTRY_RULES = [
    (r"currentversion\run",           "Registry Run key persistence",           "T1547.001", 75),
    (r"currentversion\runonce",       "Registry RunOnce persistence",            "T1547.001", 70),
    (r"windows defender",             "Defender registry policy modified",       "T1562.001", 88),
    (r"control\lsa",                  "LSA registry modified — credential theft","T1003.001", 85),
    (r"image file execution options", "IFEO debugger key — process hijack",      "T1546.012", 82),
    (r"winlogon",                     "Winlogon registry key modified",          "T1547.004", 75),
    (r"\services\\",                  "New service registry key created",        "T1543.003", 68),
    (r"appinit_dlls",                 "AppInit_DLLs modified — DLL persistence", "T1546.010", 80),
    (r"clsid",                        "COM registry key modified — COM hijack",  "T1546.015", 65),
]


def _handle_etw_registry(system_id: str, event: dict):
    process   = event.get("process",    "unknown")
    key_path  = event.get("key_path",   "").lower()
    value     = event.get("value_name", "")
    action    = event.get("action",     "set_value")

    if not key_path:
        return

    for path_fragment, description, technique, score in _REGISTRY_RULES:
        if path_fragment in key_path:
            alert = _make_alert(
                sid=system_id,
                proc=process,
                score=score,
                confidence="HIGH",
                reason=(f"ETW Registry: {description} — "
                        f"{process} wrote to '{key_path}' "
                        f"(value: {value!r}, action: {action})"),
                technique=technique,
            )
            _emit(alert)
            return   # one alert per write — most specific rule wins


# ── ScriptBlock content analyser (ETW) ───────────────────────────────────────

# Patterns applied to decoded ScriptBlock content.
# These catch obfuscated payloads that evade cmdline-based L1 rules entirely
# because the encoding/obfuscation is resolved before this point.
_SCRIPTBLOCK_PATTERNS = [
    # Credential dumping in memory
    ("sekurlsa",                    95, "T1003.001", "Mimikatz sekurlsa in decoded PS script"),
    ("lsadump",                     95, "T1003.001", "Mimikatz lsadump in decoded PS script"),
    # AMSI bypass
    ("amsiutils",                   90, "T1562.001", "AMSI bypass in decoded PS script"),
    ("amsiscanbuffer",               90, "T1562.001", "AMSI buffer patch in decoded PS script"),
    ("amsi.dll",                    85, "T1562.001", "AMSI DLL reference in decoded PS script"),
    # Download cradles (post-decode — catches string-concat obfuscation)
    ("new-object net.webclient",    80, "T1105",     "WebClient download in decoded PS script"),
    ("downloadstring(",             80, "T1105",     "DownloadString in decoded PS script"),
    ("downloadfile(",               80, "T1105",     "DownloadFile in decoded PS script"),
    ("invoke-webrequest",           70, "T1105",     "IWR download in decoded PS script"),
    # Reflection / assembly load
    ("[reflection.assembly]::load", 82, "T1620",     "Reflective assembly load in PS script"),
    # Scheduled task / persistence via PS
    ("register-scheduledtask",      72, "T1053.005", "Scheduled task created in PS script"),
    # Shadow copy deletion
    ("remove-wmiobject.*shadow",    88, "T1490",     "Shadow copy deletion in PS script"),
    ("win32_shadowcopy",            85, "T1490",     "Shadow copy access in PS script"),
    # Defender disable
    ("disablerealtimemonitoring",   90, "T1562.001", "Defender disabled in PS script"),
    # Process injection helpers
    ("virtualalloc",                82, "T1055",     "VirtualAlloc in PS script — injection"),
    ("writeprocessmemory",          85, "T1055",     "WriteProcessMemory in PS script"),
    ("createremotethread",          88, "T1055",     "CreateRemoteThread in PS script"),
]


def _handle_etw_scriptblock(system_id: str, event: dict):
    process      = event.get("process",      "unknown")
    script_block = event.get("script_block", "").lower()

    if not script_block or len(script_block) < 10:
        return

    for pattern, score, technique, description in _SCRIPTBLOCK_PATTERNS:
        if pattern in script_block:
            alert = _make_alert(
                sid=system_id,
                proc=process,
                score=score,
                confidence="HIGH",
                reason=f"ETW ScriptBlock: {description}",
                technique=technique,
            )
            _emit(alert)
            return   # one alert per script block — highest-priority match wins

# ═════════════════════════════════════════════════════════════════════════════
# YARA HIT HANDLER
# Converts a YARA memory scan hit from the agent into a structured alert.
# Called from the /yara_hits API endpoint.
# ═════════════════════════════════════════════════════════════════════════════

def handle_yara_hit(event: dict):
    """
    Process a YARA memory scan hit and emit an alert.

    YARA hits are always high-confidence — the rule matched bytes in the
    process's private executable memory.  We score them based on the
    severity tag in the rule metadata:
      CRITICAL → score 95 (Cobalt Strike, Mimikatz, Meterpreter)
      HIGH     → score 80 (shellcode stubs, reflective injection, AMSI bypass)
      MEDIUM   → score 65 (generic PE in RWX, lower-confidence patterns)
    """
    system_id  = event.get("system_id",  "")
    process    = event.get("process",    "unknown")
    rule_name  = event.get("rule",       "unknown_rule")
    severity   = event.get("severity",   "HIGH").upper()
    mitre      = event.get("mitre",      "T1055")
    description = event.get("description", rule_name)
    addr_hex   = event.get("address_hex", "")
    region_sz  = event.get("region_size", 0)
    matched    = event.get("matched_strings", [])
    pid        = event.get("pid", 0)

    if not system_id:
        return

    score_map  = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 65}
    score      = score_map.get(severity, 80)
    confidence = "HIGH"   # YARA matches are always high confidence

    matched_str = ", ".join(matched[:3]) if matched else ""
    reason = (
        f"YARA: {description} — rule '{rule_name}' matched in "
        f"{process} (PID {pid}) at {addr_hex} "
        f"({region_sz // 1024}KB RWX private region)"
        + (f" — strings: {matched_str}" if matched_str else "")
    )

    alert = _make_alert(
        sid=system_id,
        proc=process,
        score=score,
        confidence=confidence,
        reason=reason,
        technique=mitre,
    )
    _emit(alert)

