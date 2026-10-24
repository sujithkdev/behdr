"""BehEDR administration and single-process server launcher."""
import argparse
import getpass
import logging
import os
import secrets
import signal
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))


def load_environment():
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Generate a local production configuration; never overwrites")
    user = sub.add_parser("create-user")
    user.add_argument("username")
    user.add_argument("--role", choices=["admin", "analyst", "viewer"], default="admin")
    enroll = sub.add_parser("enroll-agent")
    enroll.add_argument("system_id")
    sub.add_parser("serve")
    retention = sub.add_parser('retention-report', help='Retention inventory; does not delete recovery evidence')
    retention.add_argument('--days', type=int, default=30)
    prune = sub.add_parser('retention-apply', help='Offline bounded cleanup with mandatory verified backup')
    prune.add_argument('--days', type=int, required=True)
    prune.add_argument('--batch-size', type=int, default=1000)
    prune.add_argument('--backup', type=Path, required=True)
    prune.add_argument('--compact', action='store_true', help='Reclaim free pages offline if sufficient temporary disk space exists')
    backup = sub.add_parser("backup")
    backup.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "init":
        with (ROOT / ".env").open("x", encoding="utf-8") as config:
            config.write(f"EDR_ENV=production\nEDR_JWT_SECRET={secrets.token_urlsafe(64)}\nEDR_HOST=127.0.0.1\nEDR_PORT=5000\n")
        print("Created .env. Restrict its filesystem permissions to the server account.")
        return
    load_environment()
    from server.config import DATA_DIR, DB_PATH, HOST, PORT, validate_configuration
    validate_configuration()
    from server.database.storage import init_db
    from server.auth import init_auth, create_user, enroll_agent
    init_db()
    init_auth()
    if args.command == "create-user":
        password = getpass.getpass("Password (at least 14 characters): ")
        if password != getpass.getpass("Confirm password: "):
            raise ValueError("Passwords do not match")
        if not create_user(args.username, password, args.role):
            raise ValueError("User already exists")
        print("User created.")
    elif args.command == "enroll-agent":
        print(f"EDR_SYSTEM_ID={args.system_id}\nEDR_API_KEY={enroll_agent(args.system_id)}")
    elif args.command == "backup":
        if args.destination.exists():
            raise ValueError("Backup destination already exists")
        args.destination.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(DB_PATH) as source, sqlite3.connect(args.destination) as target:
            source.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup integrity check failed")
        print(f"Consistent SQLite backup saved to {args.destination.resolve()}")
    elif args.command == 'retention-apply':
        import json
        from server.ingestion import init_inbox
        from server.core.detector import initialize
        from server.retention import maintain
        init_inbox()
        initialize()
        print(json.dumps(maintain(args.days, args.batch_size, args.backup, args.compact), indent=2))
    elif args.command == 'retention-report':
        import json
        from server.ingestion import init_inbox
        from server.operations import report
        init_inbox()
        print(json.dumps(report(args.days), indent=2))
    elif args.command == "serve":
        from server.runtime_lock import exclusive_instance
        from server import create_app
        from waitress import serve
        logging.basicConfig(level=logging.INFO)
        def terminate(signum, frame):
            # Waitress catches SystemExit and shuts down its request dispatcher.
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, terminate)
        with exclusive_instance(Path(DATA_DIR) / "server.lock"):
            try:
                serve(create_app(), host=HOST, port=PORT, threads=16, connection_limit=100,
                      max_request_body_size=2 * 1024 * 1024, channel_timeout=30)
            finally:
                from server.ingestion import stop_worker
                stop_worker()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, FileExistsError) as error:
        raise SystemExit(str(error))
