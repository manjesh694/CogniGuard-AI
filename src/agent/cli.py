"""
CogniGuard AI - Unified Command-Line Interface
Author: CogniGuard Engineering Team
Description: Entrypoint for pre-install repo scanning, 24/7 guardian daemon,
             local security API bridge, and full-system disk audits.
"""

import argparse
import json
import os
import sys
from typing import List, Optional

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.full_system_scanner import FullSystemGuardian  # noqa: E402
from agent.guardian_daemon_24x7 import CogniGuard24x7Daemon  # noqa: E402
from agent.quarantine import QuarantineManager  # noqa: E402
from agent.repo_scanner import format_scan_sarif, scan_repository  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level cogniguard CLI parser."""
    parser = argparse.ArgumentParser(
        prog="cogniguard",
        description="CogniGuard AI — Zero-Entry Autonomous Cyber Defense CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser(
        "scan",
        help="Scan a repository or AI skill directory before installing",
    )
    scan_p.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target directory to scan (default: current directory)",
    )
    scan_p.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on REVIEW_REQUIRED as well as DO_NOT_INSTALL",
    )
    scan_p.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (text, json, or sarif)",
    )

    daemon_p = subparsers.add_parser(
        "daemon",
        help="Run the 24/7 background Downloads & Honeypot guardian",
    )
    daemon_p.add_argument(
        "--test",
        action="store_true",
        help="Run 2 monitoring cycles and exit cleanly",
    )

    bridge_p = subparsers.add_parser(
        "bridge",
        help="Start the local FastAPI security telemetry & inspection bridge",
    )
    bridge_p.add_argument("--host", default="127.0.0.1", help="Bind host")
    bridge_p.add_argument("--port", type=int, default=8765, help="Bind port")

    sys_p = subparsers.add_parser(
        "system-scan",
        help="Run a full-system disk audit for disguised executables",
    )
    sys_p.add_argument(
        "--max-files",
        type=int,
        default=500,
        help="Maximum files to inspect (default: 500)",
    )

    q_p = subparsers.add_parser(
        "quarantine",
        help="Inspect, restore, or shred quarantined files",
    )
    q_sub = q_p.add_subparsers(dest="q_action", required=True)
    q_list = q_sub.add_parser("list", help="List quarantined items")
    q_list.add_argument("--status", choices=["QUARANTINED", "RESTORED", "SHREDDED"], default=None)
    q_restore = q_sub.add_parser("restore", help="Restore a quarantined item by ID")
    q_restore.add_argument("qid", help="Quarantine ID")
    q_shred = q_sub.add_parser("shred", help="Permanently delete a quarantined item by ID")
    q_shred.add_argument("qid", help="Quarantine ID")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Execute the cogniguard CLI and return an exit status code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        quiet_mode = args.format in {"json", "sarif"}
        try:
            report = scan_repository(args.target, quiet=quiet_mode)
        except (ValueError, RuntimeError) as exc:
            print(f"[!] {exc}", file=sys.stderr if quiet_mode else sys.stdout)
            return 1
        if report is None:
            return 1
        if args.format == "json":
            print(json.dumps(report, indent=2))
        elif args.format == "sarif":
            print(json.dumps(format_scan_sarif(report), indent=2))
        if report["verdict"] == "DO_NOT_INSTALL":
            return 2
        if args.strict and report["verdict"] == "REVIEW_REQUIRED":
            return 2
        return 0

    if args.command == "daemon":
        daemon = CogniGuard24x7Daemon()
        daemon.run_forever(max_cycles=2 if args.test else 0)
        return 0

    if args.command == "bridge":
        import uvicorn
        from agent.api_bridge import app

        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    if args.command == "system-scan":
        scanner = FullSystemGuardian()
        scanner.scan_full_system(max_files=args.max_files)
        return 2 if scanner.flagged_threats else 0

    if args.command == "quarantine":
        mgr = QuarantineManager()
        if args.q_action == "list":
            items = mgr.store.list_quarantine_items(status=args.status)
            if not items:
                print("Quarantine vault is empty.")
            for item in items:
                print(f"[{item['id']}] {item['status']} | {item['filename']} | sha256:{item['sha256'][:16]}...")
            return 0
        if args.q_action == "restore":
            restored = mgr.restore_file(args.qid)
            if not restored:
                print(f"[!] Cannot restore item: {args.qid}")
                return 1
            print(f"✅ Restored {restored['filename']} to {restored['original_path']}")
            return 0
        if args.q_action == "shred":
            if not mgr.shred_file(args.qid):
                print(f"[!] Quarantine item not found: {args.qid}")
                return 1
            print(f"🗑️ Permanently shredded item: {args.qid}")
            return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
