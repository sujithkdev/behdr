"""Strict, stateless Sigma process-creation subset; not a general Sigma backend."""
import hashlib
from pathlib import Path
import re

import yaml

CATALOG = Path(__file__).resolve().parent.parent / 'sigma_rules'
FIELDS = {'Image': 'exe_path', 'CommandLine': 'cmdline', 'ParentImage': 'parent_exe_path'}
RULES = ()


class StrictLoader(yaml.SafeLoader):
    """Do not silently discard duplicate keys or accept merge-key overrides."""


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError('Sigma mapping keys must be unique strings')
        result[key] = loader.construct_object(value_node)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def compile_rule(raw, digest):
    allowed = {'title', 'id', 'status', 'description', 'author', 'license', 'references',
               'logsource', 'detection', 'falsepositives', 'level', 'tags'}
    if not isinstance(raw, dict) or set(raw) - allowed:
        raise ValueError('Unsupported Sigma top-level structure')
    for key in ('title', 'id', 'author', 'license'):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise ValueError('Missing Sigma metadata: ' + key)
    if raw.get('logsource') != {'category': 'process_creation', 'product': 'windows'}:
        raise ValueError('Unsupported Sigma logsource')
    if raw.get('level') not in {'medium', 'high', 'critical'}:
        raise ValueError('Unsupported Sigma level')
    detection = raw.get('detection')
    if not isinstance(detection, dict):
        raise ValueError('Invalid Sigma detection')
    condition = detection.get('condition', '')
    if not isinstance(condition, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]*', condition):
        raise ValueError('Only a single named selection is supported')
    if set(detection) != {'condition', condition}:
        raise ValueError('Unsupported or unused Sigma selection')
    selection = detection[condition]
    if not isinstance(selection, dict) or not selection:
        raise ValueError('Selection must be a nonempty mapping')
    predicates = []
    for key, values in selection.items():
        if not isinstance(key, str):
            raise ValueError('Invalid field')
        field, *mods = key.split('|')
        if field not in FIELDS or mods not in ([], ['contains'], ['endswith'], ['startswith'], ['contains', 'all']):
            raise ValueError('Unsupported Sigma field/modifier: ' + key)
        values = values if isinstance(values, list) else [values]
        if not values or any(not isinstance(v, str) or not v or '*' in v or '?' in v for v in values):
            raise ValueError('Only nonempty literal strings without wildcards are supported')
        predicates.append((FIELDS[field], mods, [v.casefold() for v in values]))
    return {**raw, 'sha256': digest, '_predicates': predicates}


def load_catalog(directory=CATALOG):
    global RULES
    compiled = []
    for path in sorted(Path(directory).glob('*.yml')):
        data = path.read_bytes()
        if len(data) > 65536:
            raise ValueError('Sigma rule exceeds 64 KiB')
        compiled.append(compile_rule(yaml.load(data, Loader=StrictLoader), hashlib.sha256(data).hexdigest()))
    if not compiled or len({r['id'] for r in compiled}) != len(compiled):
        raise ValueError('Empty Sigma catalog or duplicate rule IDs')
    RULES = tuple(compiled)  # publish only after the entire catalog validates


def evaluate(event):
    hits = []
    for rule in RULES:
        matched = True
        for field, mods, values in rule['_predicates']:
            actual = event.get(field)
            if not isinstance(actual, str) or not actual:
                matched = False
                break
            actual = actual.casefold()
            op = mods[0] if mods else 'equals'
            checks = [(value in actual if op == 'contains' else actual.endswith(value)
                       if op == 'endswith' else actual.startswith(value)
                       if op == 'startswith' else actual == value) for value in values]
            if not (all(checks) if 'all' in mods else any(checks)):
                matched = False
                break
        if matched:
            hits.append({key: rule[key] for key in ('id', 'title', 'author', 'license', 'level', 'sha256')})
    return {'engine': 'behedr-sigma-subset-v1', 'catalog': {r['id']: r['sha256'] for r in RULES},
            'matches': hits, 'missing_fields': sorted({field for r in RULES for field, _, _ in r['_predicates']
                                                     if not event.get(field)})}
