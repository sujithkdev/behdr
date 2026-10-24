"""Bounded source-time correlation. Scores are indicators, never probabilities."""
from collections import OrderedDict
import math
import ipaddress
import threading

from server.core.file_behavior import score_events

LATENESS = 120
MAX_KEYS = 4000
MAX_EVENTS = 2000
_windows = OrderedDict()
_lock = threading.RLock()


def instance(event, parent=False):
    prefix = 'parent_' if parent else ''
    guid = event.get(prefix + 'process_guid')
    if isinstance(guid, str) and guid.strip():
        return 'guid:' + guid.strip().lower()
    pid = event.get('ppid' if parent else 'pid', 0)
    created = event.get('parent_create_time' if parent else 'create_time', 0)
    if type(pid) is int and pid > 0 and type(created) in (int, float) and math.isfinite(created) and created > 0:
        return f'pid:{pid}:{float(created)}'
    return None


def assess(event, rules, received):
    timestamp = event.get('time')
    actor = instance(event)
    metadata = {'actor': actor, 'event_time': timestamp, 'received_at': received,
                'allowed_lateness_seconds': LATENESS}
    if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp <= 0:
        return 0, [], {**metadata, 'state': 'missing_or_invalid_time'}
    if timestamp > received + 300:
        return 0, [], {**metadata, 'state': 'future_clock_skew'}
    if actor is None:
        return 0, [], {**metadata, 'state': 'unattributed'}
    kind = 'file' if event['event'] == 'file_event' else 'network'
    if kind == 'network':
        try:
            destination = ipaddress.ip_address(event.get('remote_ip', ''))
        except ValueError:
            return 0, [], {**metadata, 'state': 'invalid_destination'}
        event = {**event, 'is_internal': destination.is_private}
    width = rules['window_seconds'] if kind == 'file' else 300
    key = (event['system_id'], actor, kind)
    with _lock:
        state = _windows.setdefault(key, {'watermark': timestamp, 'events': {}})
        _windows.move_to_end(key)
        while len(_windows) > MAX_KEYS:
            _windows.popitem(last=False)
        watermark = max(timestamp, state['watermark'])
        if timestamp < state['watermark'] - LATENESS:
            return 0, [], {**metadata, 'state': 'too_late', 'watermark': state['watermark']}
        state['watermark'] = watermark
        state['events'] = {identity: item for identity, item in state['events'].items()
                           if watermark - item['time'] < width + LATENESS}
        identity = event['event_id']
        if identity not in state['events'] and len(state['events']) >= MAX_EVENTS:
            return 0, [], {**metadata, 'state': 'capacity_exceeded', 'watermark': watermark}
        # Re-evaluate retries without counting them twice: persistence may have
        # failed after this in-memory update on an earlier attempt.
        state['events'].setdefault(identity, dict(event))
        recent = sorted((item for item in state['events'].values() if 0 <= watermark - item['time'] < width),
                        key=lambda item: (item['time'], item['event_id']))
    metadata.update(state='evaluated', watermark=watermark, evidence_ids=[item['event_id'] for item in recent])
    if kind == 'file':
        score, reasons = score_events([{'path': e.get('file_path', ''), 'action': e.get('action', '')} for e in recent], rules)
        return score, reasons, metadata
    score, reasons = 0, []
    destinations = {}
    for item in recent:
        if not item.get('is_internal', False):
            destinations.setdefault((item.get('remote_ip'), item.get('remote_port')), []).append(item['time'])
    for times in destinations.values():
        times = sorted(set(times))
        if len(times) >= 5:
            intervals = [b-a for a, b in zip(times, times[1:])]
            average = sum(intervals)/len(intervals)
            variance = sum((x-average)**2 for x in intervals)/len(intervals)
            if 1 <= average < 60 and variance < 10:
                score += 70
                reasons.append('Regular source-time connections to one external destination')
                break
    peers = {e.get('remote_ip') for e in recent if e.get('is_internal') and e.get('remote_port') in {445,3389,135,139,5985,5986}}
    if len(peers) >= 3:
        score += 80
        reasons.append('Administrative-port connections to multiple internal hosts')
    if len({ip for ip, port in destinations}) > 10:
        score += 30
        reasons.append('Multiple external destinations')
    return min(score, 100), reasons, metadata
