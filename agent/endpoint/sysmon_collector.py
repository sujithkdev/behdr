"""Opt-in Sysmon channel adapter. No installation, privilege changes or guessed actors."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import ntpath
import subprocess
import time

from eventlog import parse_xml

CHANNEL = 'Microsoft-Windows-Sysmon/Operational'
SUPPORTED = {1, 3, 11, 22}


def fingerprint(record):
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()


def normalize(record, system_id):
    system = record['Event']['System']
    kind = system['EventID']
    if kind not in SUPPORTED:
        return None
    data = {item['Name']: item['#text'] for item in record['Event']['EventData']['Data']}
    timestamp = data.get('UtcTime') or system['TimeCreated']['SystemTime']
    created = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    image = data.get('Image', '')
    event = {'system_id': system_id, 'event_id': fingerprint(record), 'source': 'sysmon',
             'source_record_id': system['EventRecordID'], 'source_event_id': kind,
             'source_channel': CHANNEL, 'time': created.timestamp(),
             'process_guid': data.get('ProcessGuid', ''), 'process': ntpath.basename(image) or 'unknown',
             'pid': int(data.get('ProcessId', '0')), 'exe_path': image, 'raw_source': record}
    if kind == 1:
        hashes = dict(part.split('=', 1) for part in data.get('Hashes', '').split(',') if '=' in part)
        event.update(event='process_spawn', parent=ntpath.basename(data.get('ParentImage', '')) or 'unknown',
                     child=event['process'], ppid=int(data.get('ParentProcessId', '0')),
                     parent_process_guid=data.get('ParentProcessGuid', ''), create_time=created.timestamp(),
                     parent_exe_path=data.get('ParentImage', ''),
                     cmdline=data.get('CommandLine', ''), cwd=data.get('CurrentDirectory', ''),
                     user=data.get('User', ''), sha256=hashes.get('SHA256', '').lower())
        return '/events', event
    if kind == 3:
        address = data.get('DestinationIp', '')
        event.update(event='network_connect', remote_ip=address, remote_port=int(data.get('DestinationPort', '0')),
                     is_internal=ipaddress.ip_address(address).is_private, protocol=data.get('Protocol', ''))
        return '/net_events', event
    if kind == 11:
        event.update(event='file_event', file_path=data.get('TargetFilename', ''), action='create')
        return '/file_events', event
    event.update(event='etw_dns_query', domain=data.get('QueryName', ''))
    return '/etw_events', event


def query(xpath='*', reverse=False, count=200):
    result = subprocess.run(['wevtutil', 'qe', CHANNEL, '/f:xml', '/e:Events', '/uni:true',
                             '/rd:' + str(reverse).lower(), '/c:' + str(count), '/q:' + xpath],
                            capture_output=True, timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError('Sysmon query failed: channel unavailable or access denied')
    return parse_xml(result.stdout.decode('utf-16').lstrip('\ufeff'))


def poll(spool, system_id, reader=query):
    state = spool.source_state('sysmon')
    cursor = state.get('record_id', 0)
    oldest = reader(count=1)
    if cursor and oldest:
        anchor = reader(xpath=f'*[System[EventRecordID={cursor}]]', count=1)
        first = oldest[0]['Event']['System']['EventRecordID']
        if not anchor or fingerprint(anchor[0]) != state.get('fingerprint'):
            state['gaps'] = state.get('gaps', 0) + 1
            state['last_gap'] = 'retention_or_reset' if first > cursor else 'log_reset'
            cursor = 0
    if cursor and not oldest:
        state.update(record_id=0, fingerprint='', gaps=state.get('gaps', 0)+1, last_gap='empty_after_bookmark')
        cursor = 0
    records = reader(xpath=f'*[System[EventRecordID>{cursor}]]')
    routed = []
    seen = set(state.get('observed_event_ids', []))
    skipped = state.get('unsupported', 0)
    for record in records:
        seen.add(record['Event']['System']['EventID'])
        mapped = normalize(record, system_id)
        if mapped:
            routed.append(mapped)
        else:
            skipped += 1
        state.update(record_id=record['Event']['System']['EventRecordID'], fingerprint=fingerprint(record))
    state.update(state='available', last_poll=time.time(), unsupported=skipped,
                 supported_event_ids=sorted(SUPPORTED), observed_event_ids=sorted(seen))
    state.pop('error', None)
    spool.commit_source('sysmon', state, routed)


def process_source_ready(state, now=None):
    age = (time.time() if now is None else now) - state.get('last_poll', 0)
    return state.get('state') == 'available' and 0 <= age < 15 and 1 in state.get('observed_event_ids', [])


def run(spool, system_id, stop):
    while not stop.is_set():
        try:
            poll(spool, system_id)
        except Exception as exc:
            state = spool.source_state('sysmon')
            state.update(state='error', error=str(exc)[:500], last_error=time.time())
            spool.commit_source('sysmon', state)
        stop.wait(2)
