# BehEDR Agent — Windows 10/11

This standalone source package runs on Windows. The server package runs on Kali/Linux.
No API key or data is bundled. Use Python 3.12 and an Administrator PowerShell for
Windows event collection. Docker is not required.

## Install

From this folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements/endpoint.txt
```

## Connect to the Kali development server

In a separate PowerShell window, replace the username and IP:

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:5000:127.0.0.1:5000 kaliuser@KALI_IP
```

Leave that window open. Kali must have its SSH server running. Verify the SSH
host fingerprint on first connection. Do not expose the development HTTP server
directly to the network.

In the agent PowerShell window:

```powershell
$env:EDR_ENV = 'development'
$env:EDR_SERVER_URL = 'http://127.0.0.1:5000'
$env:EDR_SYSTEM_ID = 'win10-lab'
$env:EDR_API_KEY = 'PASTE-KEY-FROM-SERVER-ENROLLMENT'
$env:EDR_AGENT_DATA = 'C:\ProgramData\BehEDR-Lab'
.\.venv\Scripts\python.exe endpoint/agent.py
```

Replace the key privately; never commit it to GitHub. Variables apply only to
this shell. Open http://127.0.0.1:5000 in the Windows browser for the dashboard.
Use Ctrl+C to stop the agent, then the SSH tunnel.

## Sysmon (optional until installed, recommended for event coverage)

Download Sysmon from Microsoft Sysinternals. In Administrator PowerShell install
it using deploy/sysmon-lab.xml; if already installed, update its configuration
instead. See docs/phase3-sysmon.md. Confirm the Operational log receives events.
Before starting the agent, enable the installed/configured source:

```powershell
$env:EDR_SYSMON = 'true'
$env:EDR_PROCESS_SOURCE = 'sysmon'
```

The agent falls back to polling when appropriate; polling can miss short-lived
processes. Optional YARA dependencies are not installed by this package.

## Harmless test

Start Notepad and create a text file under C:\BehEDRLab. Check actual telemetry,
not merely whether alerts appear. Inside a VMware Windows guest with Sysmon:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/phase6_guest_collect.ps1
```

This collects evidence from read-only commands; it does not prove malware accuracy.
Do not run recovery-disabling commands or real malware on the host.

Keep endpoint/ intact: agent.py imports neighboring modules. Runtime credentials,
spool databases and logs must stay private. Regenerate from the main project
after source changes. MANIFEST.json records source hashes, not a publisher signature.
