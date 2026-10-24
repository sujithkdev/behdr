"""Parse the documented XML output of Windows wevtutil."""
from xml.etree import ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_xml(text):
    # /e:Events produces one root. No DTDs or external entities are accepted.
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("DTD and entity declarations are unsupported")
    root = ET.fromstring(text)
    records = []
    for event in list(root) if root.tag.split('}')[-1] != 'Event' else [root]:
        system = event.find('e:System', NS)
        if system is None:
            continue
        execution = system.find('e:Execution', NS)
        created = system.find('e:TimeCreated', NS)
        provider = system.find('e:Provider', NS)
        records.append({'Event': {'System': {
            'EventID': int(system.findtext('e:EventID', '0', NS)),
            'EventRecordID': int(system.findtext('e:EventRecordID', '0', NS)),
            'Provider': dict(provider.attrib) if provider is not None else {},
            'Computer': system.findtext('e:Computer', '', NS),
            'Execution': dict(execution.attrib) if execution is not None else {},
            'TimeCreated': dict(created.attrib) if created is not None else {},
        }, 'EventData': {'Data': [{'Name': node.get('Name', ''), '#text': node.text or ''} for node in event.findall('e:EventData/e:Data', NS)]}}})
    return records
