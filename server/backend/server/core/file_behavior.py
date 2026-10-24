"""Pure, bounded file-behavior scoring with validated external configuration.

The separation of collection, JSON rules and scoring was inspired by
atharvavidhate12-oss/behavior-based-malware-detection-engine. This implementation
is original BehEDR code; it does not use that project's global-history scorer.
"""
import json
import ntpath
from pathlib import Path


def load_rules(path):
    rules = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = {"window_seconds", "minimum_events", "high_modifications", "mass_modifications",
                "minimum_extension_files", "high_score", "mass_score", "extension_score",
                "note_bonus", "note_keywords", "note_extensions", "suspicious_extensions"}
    if not isinstance(rules, dict) or set(rules) != expected:
        raise ValueError("File behavior rules have missing or unknown fields")
    list_fields = {"note_keywords", "note_extensions", "suspicious_extensions"}
    for key in expected - list_fields:
        if type(rules[key]) is not int or not 1 <= rules[key] <= 10000:
            raise ValueError(f"Invalid positive integer: {key}")
    for key in ("high_score", "mass_score", "extension_score", "note_bonus"):
        if rules[key] > 100:
            raise ValueError(f"Score exceeds 100: {key}")
    if not rules["minimum_events"] <= rules["high_modifications"] < rules["mass_modifications"]:
        raise ValueError("File modification thresholds must be ordered")
    if rules["minimum_extension_files"] < rules["minimum_events"]:
        raise ValueError("Extension evidence must cover at least minimum_events files")
    for key in list_fields:
        values = rules[key]
        if not isinstance(values, list) or not values or any(
            not isinstance(value, str) or not value.strip() for value in values
        ):
            raise ValueError(f"Invalid string list: {key}")
        if key != "note_keywords" and any(not value.startswith(".") for value in values):
            raise ValueError(f"Extensions must start with a dot: {key}")
        rules[key] = [value.casefold() for value in values]
    return rules


def score_events(events, rules):
    """Score an already windowed set of observations, without claiming a writer.

    Rates count distinct modified paths, not duplicate deliveries. A note-like
    filename contributes only when bulk modifications or multiple suspicious
    extensions corroborate it. Scores are priorities, not malware probabilities.
    """
    if len(events) < rules["minimum_events"]:
        return 0, []
    modified = {
        ntpath.normcase(ntpath.normpath(event["path"]))
        for event in events if event["action"] in {"modify", "encrypt", "write"}
    }
    extension_paths = {
        ntpath.normcase(ntpath.normpath(event["path"])) for event in events
        if ntpath.splitext(event["path"])[1].casefold() in rules["suspicious_extensions"]
    }
    score, reasons = 0, []
    if len(modified) > rules["mass_modifications"]:
        score += rules["mass_score"]
        reasons.append(f"Mass file modification ({len(modified)} distinct paths)")
    elif len(modified) > rules["high_modifications"]:
        score += rules["high_score"]
        reasons.append(f"High file modification rate ({len(modified)} distinct paths)")
    if len(extension_paths) >= rules["minimum_extension_files"]:
        score += rules["extension_score"]
        reasons.append(f"Suspicious extensions across {len(extension_paths)} distinct paths")
    if score:
        for event in events:
            name = ntpath.basename(event["path"]).casefold()
            if ntpath.splitext(name)[1] in rules["note_extensions"] and any(
                keyword in name for keyword in rules["note_keywords"]
            ):
                score += rules["note_bonus"]
                reasons.append(f"Note-like filename accompanying file activity: {event['path']}")
                break
    return min(score, 100), reasons
