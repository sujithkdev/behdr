# BehEDR — Server and Windows Agent

Separate source packages for a Windows behavioral threat-monitoring research
project. No Docker is required for the development lab setup.

| Package | Machine | Entry point | Setup |
|---|---|---|---|
| Server | Kali/Linux with Python 3.12 | `python manage.py serve` from server/ | [Server README](server/README.md) |
| Agent | Windows 10/11 with Python 3.12 | `python endpoint/agent.py` from agent/ | [Agent README](agent/README.md) |

```text
server/
  manage.py
  backend/server/
  rules/
  requirements/
  docs/
agent/
  endpoint/
  requirements/
  deploy/sysmon-lab.xml
  tools/phase6_guest_collect.ps1
  docs/
```

Clone this repository, or download server.zip and agent.zip from
[Releases](https://github.com/sujithkdev/behdr/releases).
Follow each package's README to install dependencies and configure enrollment.
No API key, administrator account, database, logs or virtual environment is bundled.
Keep credentials and collected telemetry out of GitHub.

The documented development configuration binds the server to loopback and uses
an SSH tunnel from Windows. Do not expose the development HTTP listener directly
to the network. Production deployment requires suitable HTTPS configuration.

## Status and limits

This project is not a certified enterprise EDR. Real Windows malware detection
accuracy, false-positive rates and external comparative results remain unproven.
Synthetic regression tests validate software behavior, not malware effectiveness.
Automatic containment, network isolation and experimental trained models are not
supported release capabilities. Historical inactive modules are included with
the server source and must not be interpreted as enabled features.

Each package's MANIFEST.json records file hashes for integrity checking. These
hashes are not a publisher signature. This repository contains a split snapshot
of the development project; update both packages together when interfaces change.

No repository-wide license grant is added by this upload. Individual bundled
license notices remain with their respective files.
