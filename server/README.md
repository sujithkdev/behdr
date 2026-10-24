# BehEDR Server — Kali/Linux

This folder is a standalone server source package. No Docker is required.
Python 3.12 is the tested interpreter. Windows endpoint files are in the separate
agent package. No credentials, administrator account or database is bundled.

## Install and run (development lab via SSH)

Run from this folder:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements/server.lock
.venv/bin/python manage.py init
export EDR_ENV=development
export EDR_HOST=127.0.0.1
export EDR_PORT=5000
.venv/bin/python manage.py create-user labadmin
.venv/bin/python manage.py enroll-agent win10-lab
.venv/bin/python manage.py serve
```

Run init only once. Save the enrollment credential privately. Enrolling the
same endpoint again rotates its key. Keep the server window open. Set the three
environment variables again in a new shell. The development server must remain
bound to loopback; connect from Windows using the SSH instructions in agent/README.md
from the separate package. Production requires a properly configured HTTPS proxy.

Dashboard: http://127.0.0.1:5000 on Kali, or through the Windows SSH tunnel.
Kali needs an SSH server reachable from the Windows guest for tunnel access.
Use Ctrl+C to stop. Runtime data defaults to var/server; never upload it to GitHub.

## Files

- manage.py: launcher, users, enrollment, backups and maintenance.
- backend/server/: API, dashboard and detection code (including inactive historical modules).
- rules/: detector configuration; keep beside backend and manage.py.
- requirements/server.lock: pinned server dependencies.
- docs/: operational and implementation limitations.
- MANIFEST.json: packaged file hashes, not a cryptographic publisher signature.

This is a behavior-monitoring research project, not a validated enterprise EDR.
Real Windows detection accuracy and external comparisons remain unmeasured.
Do not enable unsupported ML, automatic containment or legacy integrations.
The root project's source remains authoritative; regenerate packages after edits.
