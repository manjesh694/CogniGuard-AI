"""Tests for SQLite storage concurrency, shared heuristics, scanners, and daemon."""

import os
import sys
import threading

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from agent.full_system_scanner import FullSystemGuardian  # noqa: E402
from agent.guardian_daemon_24x7 import CogniGuard24x7Daemon  # noqa: E402
from agent.heuristics import evaluate_filename_risk, is_disguised_executable  # noqa: E402
from agent.honeypot_trap import CogniGuardHoneypot  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402


def test_sqlite_store_concurrent_writes(tmp_path):
    store = CogniGuardStore(str(tmp_path / "concurrent.db"))
    errors = []

    def worker(tid: int):
        try:
            for idx in range(10):
                store.record_audit_event({
                    "verdict": "INTRUSION_DETECTED" if idx % 2 == 0 else "SAFE",
                    "threat_score": 0.96 if idx % 2 == 0 else 0.04,
                    "action_taken": "QUARANTINE" if idx % 2 == 0 else "ALLOW",
                    "filename": f"thread_{tid}_file_{idx}.exe",
                })
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert not errors
    summary = store.get_telemetry_summary("1.0.3")
    assert summary["total_events"] == 80
    assert summary["threats_blocked"] == 40
    assert summary["clean_events"] == 40


def test_heuristics_and_full_system_scanner(tmp_path):
    assert evaluate_filename_risk("offer.pdf.exe")["threat_score"] == 0.99
    assert evaluate_filename_risk("setup.exe")["verdict"] == "INTRUSION_DETECTED"
    assert evaluate_filename_risk("notes.txt")["verdict"] == "SAFE"

    fake_pdf = tmp_path / "invoice.pdf"
    fake_pdf.write_bytes(b"MZ" + b"\x00" * 128)
    real_pdf = tmp_path / "clean.pdf"
    real_pdf.write_bytes(b"%PDF-1.7\n" + b"0" * 128)
    double_ext = tmp_path / "resume.pdf.exe"
    double_ext.write_text("dummy", encoding="utf-8")

    assert is_disguised_executable(str(fake_pdf)) is True
    assert is_disguised_executable(str(real_pdf)) is False

    guardian = FullSystemGuardian()
    guardian.scan_targets = [str(tmp_path)]
    guardian.scan_full_system(max_files=50)
    flagged_names = {os.path.basename(t["file"]) for t in guardian.flagged_threats}
    assert flagged_names == {"invoice.pdf", "resume.pdf.exe"}


def test_honeypot_deploy_and_daemon_detection(tmp_path, capsys):
    trap = CogniGuardHoneypot()
    trap.desktop_dir = str(tmp_path)
    trap.honeypot_path = str(tmp_path / trap.honeypot_filename)
    trap.deploy_trap()
    assert os.path.exists(trap.honeypot_path)
    trap.trigger_honeypot_alarm("evil.exe", pid=4242)
    captured = capsys.readouterr().out
    assert "INTRUDER CAUGHT" in captured

    store = CogniGuardStore(str(tmp_path / "daemon.db"))
    downloads_dir = tmp_path / "Downloads"
    downloads_dir.mkdir()
    bait_file = tmp_path / "bait.txt"
    bait_file.write_text("bait", encoding="utf-8")

    daemon = CogniGuard24x7Daemon(store=store)
    daemon.downloads_dir = str(downloads_dir)
    daemon.honeypot_file = str(bait_file)
    daemon._initialize_baseline()

    (downloads_dir / "dropped_stealer.exe").write_text("bad", encoding="utf-8")
    daemon.check_cycle()

    logs = store.list_audit_logs()
    assert len(logs) == 1
    assert logs[0]["filename"] == "dropped_stealer.exe"
    assert logs[0]["verdict"] == "INTRUSION_DETECTED"
