"""
CogniGuard AI - Unified Command-Line Interface
Author: CogniGuard Engineering Team
Description: Entrypoint for pre-install repo scanning, 24/7 guardian daemon,
             local security API bridge, and full-system disk audits.
"""

import argparse
import importlib
import json
import os
import platform
import re
import shutil
import stat
import sys
from typing import List, Optional

_AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.dirname(_AGENT_DIR)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.defense_council import AutonomousDefenseCouncil  # noqa: E402
from agent.full_system_scanner import FullSystemGuardian  # noqa: E402
from agent.guardian_daemon_24x7 import CogniGuard24x7Daemon  # noqa: E402
from agent.quarantine import QuarantineManager  # noqa: E402
from agent.repo_scanner import format_scan_sarif, scan_repository  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402
from agent.vault_guardian import CogniGuardAgent  # noqa: E402


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
    daemon_p.add_argument(
        "--sweep-every",
        type=int,
        default=30,
        help="Run live process/C2/kill-chain sweep every N cycles (default: 30, 0 disables)",
    )

    bridge_p = subparsers.add_parser(
        "bridge",
        help="Start the local FastAPI security telemetry & inspection bridge",
    )
    bridge_p.add_argument("--host", default="127.0.0.1", help="Bind host")
    bridge_p.add_argument("--port", type=int, default=8765, help="Bind port")

    sys_p = subparsers.add_parser(
        "system-scan",
        help="Run a full-system disk audit for disguised executables and IOC matches",
    )
    sys_p.add_argument(
        "--max-files",
        type=int,
        default=500,
        help="Maximum files to inspect (default: 500)",
    )
    sys_p.add_argument(
        "--quarantine",
        action="store_true",
        help="Automatically isolate flagged files in the SHA-256 quarantine vault",
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

    proc_p = subparsers.add_parser(
        "process-audit",
        help="Audit live running OS processes via psutil for suspicious executions",
    )
    proc_p.add_argument("--json", action="store_true", help="Output process audit as JSON")
    proc_p.add_argument("--terminate", action="store_true", help="Terminate flagged suspicious processes")

    hook_p = subparsers.add_parser(
        "install-hook",
        help="Install a Git pre-commit hook that blocks risky code via cogniguard scan --strict",
    )
    hook_p.add_argument("repo_path", nargs="?", default=".", help="Path to git repository")
    hook_p.add_argument("--force", action="store_true", help="Overwrite an existing pre-commit hook")

    ioc_p = subparsers.add_parser(
        "ioc",
        help="Manage the SHA-256 Threat Intelligence IOC blocklist",
    )
    ioc_sub = ioc_p.add_subparsers(dest="ioc_action", required=True)
    ioc_sub.add_parser("list", help="List blocked SHA-256 IOC hashes")
    ioc_add = ioc_sub.add_parser("add", help="Add a malicious SHA-256 hash to the blocklist")
    ioc_add.add_argument("sha256", help="64-character hex SHA-256 digest")
    ioc_add.add_argument("--label", required=True, help="Threat label (e.g. RedLine_Dropper)")
    ioc_add.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM"], default="CRITICAL")
    ioc_rm = ioc_sub.add_parser("remove", help="Remove a SHA-256 hash from the blocklist")
    ioc_rm.add_argument("sha256", help="64-character hex SHA-256 digest")

    doc_p = subparsers.add_parser(
        "doctor",
        help="Run self-diagnostics on CogniGuard environment, DB, git, and security posture",
    )
    doc_p.add_argument("--json", action="store_true", help="Output diagnostics as JSON")

    net_p = subparsers.add_parser(
        "network-audit",
        help="Audit active outbound network sockets for C2 ports or temp-binary beacons",
    )
    net_p.add_argument("--json", action="store_true", help="Output network audit report as JSON")
    net_p.add_argument("--terminate", action="store_true", help="Terminate processes owning flagged C2 sockets")

    kc_p = subparsers.add_parser(
        "killchain-audit",
        help="Correlate multi-stage threat events in SQLite within a time window",
    )
    kc_p.add_argument("--window", type=int, default=300, help="Correlation time window in seconds (default: 300)")
    kc_p.add_argument("--json", action="store_true", help="Output kill-chain correlation report as JSON")

    dc_p = subparsers.add_parser(
        "council",
        help="Run CogniGuard's Multi-Agent Autonomous Defense Council across static, runtime, and kill-chain agents",
    )
    dc_p.add_argument("--target", default=None, help="Optional workspace/repository path for StaticSupplyChainAgent")
    dc_p.add_argument("--window", type=int, default=300, help="Kill-chain time window in seconds (default: 300)")
    dc_p.add_argument("--remediate", action="store_true", help="Contain detected threats and verify clean post-state")
    dc_p.add_argument("--no-runtime", action="store_true", help="Skip live OS process & network socket inspection")
    dc_p.add_argument("--json", action="store_true", help="Output council investigation report as JSON")

    st_p = subparsers.add_parser(
        "startup",
        help="Install, inspect, or remove user-level OS login autostart launcher for CogniGuard",
    )
    st_p.add_argument("--mode", choices=["daemon", "bridge"], default="daemon", help="Target background service")
    st_group = st_p.add_mutually_exclusive_group()
    st_group.add_argument("--install", action="store_true", help="Write launcher script into user startup folder")
    st_group.add_argument("--remove", action="store_true", help="Remove launcher script from user startup folder")
    st_p.add_argument("--json", action="store_true", help="Output startup configuration result as JSON")

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
        daemon = CogniGuard24x7Daemon(sweep_interval_cycles=args.sweep_every)
        daemon.run_forever(max_cycles=2 if args.test else 0)
        return 0

    if args.command == "bridge":
        import uvicorn
        from agent.api_bridge import app

        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    if args.command == "system-scan":
        store = CogniGuardStore()
        mgr = QuarantineManager(store=store)
        scanner = FullSystemGuardian(store=store, quarantine_manager=mgr, auto_quarantine=args.quarantine)
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

    if args.command == "process-audit":
        agent = CogniGuardAgent()
        report = agent.audit_live_processes()
        if args.terminate and report["flagged"]:
            report["remediation"] = agent.terminate_flagged_processes(report["flagged"])
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"Inspected {report['processes_inspected']} live processes | Flagged: {report['flagged_count']}")
            for item in report["flagged"]:
                print(f"  🚨 PID {item['pid']} ({item['name']}) -> {item['reason']}")
        return 2 if report["flagged_count"] > 0 else 0

    if args.command == "install-hook":
        git_dir = os.path.join(os.path.abspath(args.repo_path), ".git")
        if not os.path.isdir(git_dir):
            print(f"[!] Not a git repository: {args.repo_path}")
            return 1
        hooks_dir = os.path.join(git_dir, "hooks")
        os.makedirs(hooks_dir, exist_ok=True)
        hook_path = os.path.join(hooks_dir, "pre-commit")
        if os.path.exists(hook_path) and not args.force:
            print(f"[!] pre-commit hook already exists at {hook_path} (use --force to overwrite)")
            return 1
        hook_script = (
            "#!/usr/bin/env sh\n"
            "if command -v cogniguard >/dev/null 2>&1; then\n"
            "  cogniguard scan --strict .\n"
            "else\n"
            "  python -m agent.cli scan --strict .\n"
            "fi\n"
        )
        with open(hook_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(hook_script)
        try:
            current_mode = os.stat(hook_path).st_mode
            os.chmod(hook_path, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass
        print(f"✅ Installed CogniGuard pre-commit hook at: {hook_path}")
        return 0

    if args.command == "ioc":
        store = CogniGuardStore()
        if args.ioc_action == "list":
            items = store.list_iocs()
            if not items:
                print("IOC blocklist is empty.")
            for item in items:
                print(f"[{item['severity']}] {item['sha256']} | {item['label']} ({item['added_at']})")
            return 0
        if args.ioc_action == "add":
            if not re.match(r"^[0-9a-fA-F]{64}$", args.sha256.strip()):
                print("[!] sha256 must be a 64-character hex digest")
                return 1
            rec = store.add_ioc(args.sha256, args.label, args.severity)
            print(f"🛡️ Added IOC: {rec['sha256']} ({rec['label']})")
            return 0
        if args.ioc_action == "remove":
            if not store.delete_ioc(args.sha256):
                print(f"[!] IOC not found: {args.sha256}")
                return 1
            print(f"🗑️ Removed IOC: {args.sha256.lower()}")
            return 0

    if args.command == "doctor":
        store = CogniGuardStore()
        mgr = QuarantineManager(store=store)
        deps = {}
        for mod in ("fastapi", "uvicorn", "pydantic", "psutil", "requests"):
            try:
                importlib.import_module(mod)
                deps[mod] = True
            except ImportError:
                deps[mod] = False
        summary = store.get_telemetry_summary("1.0.4")
        diag = {
            "status": "OK" if all(deps.values()) else "DEGRADED",
            "python": platform.python_version(),
            "platform": platform.system(),
            "git_available": shutil.which("git") is not None,
            "db_path": store.db_path,
            "quarantine_dir": mgr.vault_dir,
            "api_key_enabled": bool(os.environ.get("COGNIGUARD_API_KEY", "").strip()),
            "webhook_configured": bool(
                os.environ.get("COGNIGUARD_WEBHOOK_URL", "").strip()
                or store.get_setting("alert_webhook_url")
            ),
            "dependencies": deps,
            "telemetry": summary,
        }
        if args.json:
            print(json.dumps(diag, indent=2))
        else:
            print(f"CogniGuard Doctor: {diag['status']} | Python {diag['python']} ({diag['platform']})")
            print(f"  git: {'OK' if diag['git_available'] else 'MISSING'} | DB: {diag['db_path']}")
            print(f"  Vault: {diag['quarantine_dir']} | API Key Auth: {diag['api_key_enabled']}")
        return 0 if diag["status"] == "OK" else 1

    if args.command == "network-audit":
        agent = CogniGuardAgent()
        result = agent.audit_network_connections()
        if args.terminate and result["flagged"]:
            result["remediation"] = agent.terminate_flagged_processes(result["flagged"])
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(
                f"CogniGuard Network Audit: {result['status']} "
                f"({result['connections_inspected']} outbound sockets inspected, {result['flagged_count']} flagged)"
            )
            for item in result["flagged"]:
                print(f"  [!] PID {item['pid']} ({item['process_name']}) -> {item['remote_ip']}:{item['remote_port']} [{item['reason']}]")
        return 2 if result["flagged_count"] > 0 else 0

    if args.command == "killchain-audit":
        store = CogniGuardStore()
        agent = CogniGuardAgent()
        report = agent.audit_kill_chains(store=store, window_seconds=args.window)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(
                f"CogniGuard Kill-Chain Audit: {report['status']} ({report['severity']}) "
                f"| Stages: {', '.join(report['stages_detected']) or 'none'}"
            )
        return 2 if report["status"] == "KILL_CHAIN_DETECTED" else 0

    if args.command == "council":
        store = CogniGuardStore()
        mgr = QuarantineManager(store=store)
        council = AutonomousDefenseCouncil(store=store, quarantine_manager=mgr)
        result = council.investigate(
            target_dir=args.target,
            window_seconds=args.window,
            auto_remediate=args.remediate,
            include_runtime=not args.no_runtime,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"CogniGuard Defense Council: {result['status']}")
            for step in result["reasoning_trace"]:
                print(f"  [{step['agent']}] {step['summary']}")
        return 2 if result["status"] == "THREATS_DETECTED" else 0

    if args.command == "startup":
        is_windows = platform.system().lower().startswith("win")
        custom_dir = os.environ.get("COGNIGUARD_STARTUP_DIR", "").strip()
        if custom_dir:
            startup_dir = custom_dir
        elif is_windows:
            appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
            startup_dir = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        else:
            startup_dir = os.path.join(os.path.expanduser("~"), ".config", "autostart")

        filename = "cogniguard_ai.cmd" if is_windows else "cogniguard_ai.desktop"
        target_path = os.path.join(startup_dir, filename)
        py_exe = sys.executable
        cli_script = os.path.abspath(__file__)
        if is_windows:
            launcher_content = f'@echo off\nstart "" /b "{py_exe}" "{cli_script}" {args.mode}\n'
        else:
            launcher_content = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=CogniGuard AI Guardian\n"
                f'Exec="{py_exe}" "{cli_script}" {args.mode}\n'
                "X-GNOME-Autostart-enabled=true\n"
            )

        action = "PREVIEW"
        if args.install:
            os.makedirs(startup_dir, exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(launcher_content)
            action = "INSTALLED"
        elif args.remove:
            if os.path.exists(target_path):
                os.remove(target_path)
                action = "REMOVED"
            else:
                action = "NOT_FOUND"

        payload = {
            "status": "OK",
            "action": action,
            "mode": args.mode,
            "launcher_path": target_path,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"CogniGuard Startup [{action}] ({args.mode}): {target_path}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
