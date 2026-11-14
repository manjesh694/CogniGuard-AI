import json
import os
import sys
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from agent import api_bridge
from agent.ai_explainer import AgenticThreatExplainer
from agent.alerts import (
    WebhookDispatcher,
    format_alert_payload,
    format_telegram_message,
    validate_webhook_url,
)
from agent.cli import main as cli_main
from agent.tray_daemon import generate_shield_icon


def test_telegram_and_webhook_payload_formatting():
    event = {
        "severity": "CRITICAL",
        "filename": "apply.loanzap.in",
        "reason": "Predatory Instant Loan Fraud & Unauthorized Disbursal Lure",
        "threat_score": 0.99,
        "action_taken": "PAYLOAD_NEUTRALIZED",
        "source_url": "https://apply.loanzap.in/",
        "timestamp": "2026-11-15 00:00:00",
    }

    # Telegram format
    tg_text = format_telegram_message(event)
    assert "COGNIGUARD AI SOC ALERT" in tg_text
    assert "CRITICAL" in tg_text
    assert "apply.loanzap.in" in tg_text
    assert "0 Bytes Leaked" in tg_text

    # Webhook format (Slack / Discord)
    payload = format_alert_payload(event)
    assert "text" in payload
    assert len(payload["embeds"]) == 1
    assert payload["embeds"][0]["title"] == "🚨 CogniGuard AI SOC Alert — CRITICAL"
    assert len(payload["blocks"]) == 2


def test_agentic_threat_explainer():
    explainer = AgenticThreatExplainer()

    # 1. Predatory loan test
    loan_report = explainer.explain("https://apply.loanzap.in/ fast approval loan")
    assert loan_report.category == "Predatory Instant Loan & Micro-Finance Trap"
    assert loan_report.urgency_level == "CRITICAL"
    assert any("Manufactured Financial Relief" in t for t in loan_report.psychological_triggers)
    assert any("1930" in a for a in loan_report.recommended_actions)

    # 2. Bank KYC test
    kyc_report = explainer.explain("Your SBI account will be suspended. Update KYC immediately.")
    assert "Banking Impersonation" in kyc_report.category
    assert kyc_report.urgency_level == "CRITICAL"

    # 3. Disguised file test
    file_report = explainer.explain("invoice_receipt.pdf.exe")
    assert "Disguised Malware Dropper" in file_report.category
    assert file_report.urgency_level == "CRITICAL"


def test_tray_shield_icon_generator():
    icon_active = generate_shield_icon(size=64, active=True)
    assert icon_active.size == (64, 64)
    icon_alert = generate_shield_icon(size=32, active=False)
    assert icon_alert.size == (32, 32)


def test_cli_explain(capsys):
    ret = cli_main(["explain", "https://apply.loanzap.in/", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["category"] == "Predatory Instant Loan & Micro-Finance Trap"
    assert data["urgency_level"] == "CRITICAL"


def test_api_threat_explain():
    from fastapi.testclient import TestClient

    client = TestClient(api_bridge.app)
    resp = client.post(
        "/api/v1/threat/explain",
        json={"content": "https://apply.loanzap.in/ instant approval disbursal"},
    )
    assert resp.status_code == 200
    res = resp.json()
    assert res["category"] == "Predatory Instant Loan & Micro-Finance Trap"
    assert res["urgency_level"] == "CRITICAL"
