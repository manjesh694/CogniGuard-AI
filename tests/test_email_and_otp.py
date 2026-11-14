import json
import os
import sys
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from agent import api_bridge
from agent.cli import main as cli_main
from agent.email_scanner import (
    send_gmail_verification_code,
    verify_email_otp,
    scan_email_spam_and_phishing,
)


def test_email_otp_send_and_verify_flow():
    test_email = "tester99@gmail.com"
    
    # 1. Send code
    res = send_gmail_verification_code(test_email)
    assert res["success"] is True
    assert res["email"] == test_email
    code = res["simulated_code"]
    assert code is not None
    assert len(code) == 6

    # 2. Test invalid code rejection
    bad_res = verify_email_otp(test_email, "000000")
    assert bad_res["valid"] is False
    assert "Incorrect verification code" in bad_res["error"]

    # 3. Test correct code acceptance
    good_res = verify_email_otp(test_email, code)
    assert good_res["valid"] is True
    assert good_res["status"] == "VERIFIED"
    assert "CG-VIP-" in good_res["vip_token"]

    # 4. Invalid email format test
    invalid_email_res = send_gmail_verification_code("not-an-email")
    assert invalid_email_res["success"] is False


def test_email_spam_and_phishing_detection():
    # Brand impersonation & coercive urgency attack
    phish_res = scan_email_spam_and_phishing(
        sender="security@accounts-g00gle.com",
        subject="Google Security Alert: Account suspended within 24 hours",
        body="Dear customer, unusual sign-in activity detected. Reset your password immediately: https://192.168.1.105/login.php",
        attachments=["urgent_security_patch.scr"]
    )
    assert phish_res["is_spam"] is True
    assert phish_res["threat_level"] == "CRITICAL_PHISHING"
    assert phish_res["risk_score"] >= 70
    assert any("BRAND_IMPERSONATION" in f for f in phish_res["findings"])
    assert any("PSYCHOLOGICAL_URGENCY" in f for f in phish_res["findings"])
    assert any("DECEPTIVE_LINKS" in f for f in phish_res["findings"])
    assert any("DANGEROUS_ATTACHMENTS" in f for f in phish_res["findings"])

    # Safe legitimate email
    safe_res = scan_email_spam_and_phishing(
        sender="newsletter@github.com",
        subject="GitHub Explore: Top projects this week",
        body="Here are the trending repositories in Python and Rust for your weekend reading.",
        attachments=[]
    )
    assert safe_res["is_spam"] is False
    assert safe_res["threat_level"] == "SAFE"
    assert safe_res["risk_score"] == 0


def test_fastapi_email_and_otp_endpoints():
    # 1. API Send Code
    req1 = api_bridge.EmailVerificationSendRequest(email="dev-lead@gmail.com")
    data = api_bridge.send_auth_code_endpoint(req1)
    assert data["success"] is True
    code = data["simulated_code"]

    # 2. API Verify Code
    req2 = api_bridge.EmailVerificationVerifyRequest(email="dev-lead@gmail.com", code=code)
    v_data = api_bridge.verify_auth_code_endpoint(req2)
    assert v_data["valid"] is True
    assert v_data["status"] == "VERIFIED"

    # 3. API Spam Scan
    req3 = api_bridge.EmailSpamScanRequest(
        sender="billing@paypal-update.xyz",
        subject="Action required immediately: Unauthorized transaction of $1,499",
        body="Confirm your account credentials at https://paypal-security-check.xyz/verify",
        attachments=["Invoice_Details.pdf.exe"]
    )
    s_data = api_bridge.scan_email_spam_endpoint(req3)
    assert s_data["is_spam"] is True
    assert s_data["threat_level"] == "CRITICAL_PHISHING"


def test_cli_email_commands(capsys):
    # CLI Send Code
    exit_code = cli_main(["send-code", "admin@gmail.com", "--json"])
    assert exit_code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["success"] is True
    code = data["simulated_code"]

    # CLI Verify Code
    v_code = cli_main(["verify-code", "admin@gmail.com", code, "--json"])
    assert v_code == 0
    v_out = capsys.readouterr().out
    v_data = json.loads(v_out)
    assert v_data["valid"] is True

    # CLI Scan Email
    s_code = cli_main([
        "scan-email",
        "--sender", "alert@service-apple.cc",
        "--subject", "Reset your password immediately",
        "--body", "Unauthorized login from China. Click here to cancel: http://10.0.0.1/auth",
        "--attachment", "SecurityKey.vbs",
        "--json"
    ])
    assert s_code == 2
    s_out = capsys.readouterr().out
    s_data = json.loads(s_out)
    assert s_data["threat_level"] == "CRITICAL_PHISHING"
