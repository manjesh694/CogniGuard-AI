"""
CogniGuard AI - Unified Command-Line Interface
Author: CogniGuard Engineering Team
Description: Entrypoint for pre-install repo scanning, 24/7 guardian daemon,
             local security API bridge, and full-system disk audits.
"""

import argparse
import os
import sys
from typing import List, Optional

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.repo_scanner import scan_repository  # noqa: E402
from agent.guardian_daemon_24x7 import CogniGuard24x7Daemon  # noqa: E402
from agent.full_system_scanner import FullSystemGuardian  # noqa: E402


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

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Execute the cogniguard CLI and return an exit status code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            report = scan_repository(args.target)
        except (ValueError, RuntimeError) as exc:
            print(f"[!] {exc}")
            return 1
        if report is None:
            return 1
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

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
