"""
CogniGuard AI - Gmail Phishing/Spam Intelligence & Verification Engine
Author: CogniGuard Engineering Team
Description: Autonomous email threat scanner (spoofing, phishing, BEC, credential harvesting)
             and Gmail OTP verification service for user authentication and VIP activation.
"""

import hashlib
import os
import re
import smtplib
import sys
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.storage import CogniGuardStore  # noqa: E402

_store = CogniGuardStore()


def get_db_connection():
    """Return a thread-safe connection from CogniGuardStore."""
    return _store._connect()

# Known trusted brands and their legitimate domain suffixes
TRUSTED_BRAND_DOMAINS = {
    "google": ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "aws.amazon.com"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "meta": ["facebook.com", "meta.com", "instagram.com"],
    "github": ["github.com"],
}

# High-urgency coercive triggers commonly used in email phishing & scams
URGENCY_TRIGGERS = [
    r"account\s+(?:suspended|locked|terminated|disabled|restricted)",
    r"(?:unauthorized|suspicious|fraudulent)\s+(?:transaction|activity|charge|login)",
    r"(?:reset|verify|confirm)\s+your\s+(?:password|identity|account|credentials)\s+immediately",
    r"within\s+(?:24|12|2|1)\s+(?:hours?|hrs?|minutes?|mins?)",
    r"action\s+required\s+immediately",
    r"urgent\s+security\s+notice",
    r"failure\s+to\s+comply\s+will\s+result\s+in",
    r"wire\s+(?:transfer|funds)\s+to\s+secure\s+account",
]

# High-risk attachment extensions
MALICIOUS_ATTACHMENT_RE = re.compile(
    r"\.(?:exe|scr|vbs|bat|cmd|iso|img|ps1|hta|wsf|cpl|jar|docm|xlsm)(?:\.exe)?$",
    re.IGNORECASE,
)
URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def ensure_email_tables() -> None:
    """Ensure SQLite table exists for OTP verification tracking."""
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_verifications (
                email TEXT PRIMARY KEY,
                code_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                expires_at REAL NOT NULL,
                verified INTEGER DEFAULT 0,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_spam_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                subject TEXT,
                threat_level TEXT NOT NULL,
                is_spam INTEGER NOT NULL,
                heuristics TEXT,
                created_at REAL NOT NULL
            )
            """
        )
        conn.commit()


def hash_otp(code: str, salt: str) -> str:
    """Hash OTP with SHA-256 and unique salt."""
    return hashlib.sha256(f"{salt}:{code}".encode("utf-8")).hexdigest()


def send_gmail_verification_code(to_email: str) -> Dict[str, Any]:
    """
    Generate and deliver a 6-digit OTP code to the target Gmail address.
    If GMAIL_USER and GMAIL_APP_PASSWORD are set, sends via Gmail SMTP (port 587).
    Otherwise, operates in simulated developer mode with instantaneous delivery token.
    """
    clean_email = to_email.strip().lower()
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", clean_email):
        return {"success": False, "error": "Invalid email format. Please provide a valid address."}

    ensure_email_tables()

    # Generate 6-digit code
    raw_code = str(int(hashlib.sha256(f"{clean_email}:{time.time()}".encode()).hexdigest(), 16) % 900000 + 100000)
    salt = hashlib.md5(f"{time.time()}:{clean_email}".encode()).hexdigest()[:8]
    code_hash = hash_otp(raw_code, salt)
    expires_at = time.time() + 600  # 10 minutes TTL

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO email_verifications
            (email, code_hash, salt, expires_at, verified, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (clean_email, code_hash, salt, expires_at, time.time()),
        )
        conn.commit()

    gmail_user = os.environ.get("GMAIL_USER")
    gmail_pwd = os.environ.get("GMAIL_APP_PASSWORD")

    smtp_sent = False
    if gmail_user and gmail_pwd:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"CogniGuard AI Security Verification Code: {raw_code}"
            msg["From"] = f"CogniGuard Security <{gmail_user}>"
            msg["To"] = clean_email

            html_body = f"""
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#081424; color:#f8fafc; padding:30px 20px; border-radius:12px; max-width:500px; margin:auto;">
                <div style="text-align:center; margin-bottom:20px;">
                    <h2 style="color:#00f5c4; margin:0;">🛡️ CogniGuard AI</h2>
                    <p style="color:#94a3b8; font-size:13px; margin:4px 0 0;">Zero-Entry Autonomous Cyber Defense</p>
                </div>
                <div style="background:#0c1d33; border:1px solid #1a3655; border-radius:10px; padding:20px; text-align:center;">
                    <p style="font-size:14px; margin-top:0;">Your 6-digit security verification code is:</p>
                    <div style="font-size:32px; font-weight:800; letter-spacing:6px; color:#00f5c4; margin:16px 0; font-family:monospace;">
                        {raw_code}
                    </div>
                    <p style="font-size:12px; color:#94a3b8; margin-bottom:0;">Code expires in 10 minutes. Never share this code with anyone.</p>
                </div>
                <div style="text-align:center; font-size:11px; color:#64748b; margin-top:20px;">
                    © 2026 CogniGuard AI Labs • Global Endpoint Defense
                </div>
            </div>
            """
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
                server.starttls()
                server.login(gmail_user, gmail_pwd)
                server.sendmail(gmail_user, clean_email, msg.as_string())
            smtp_sent = True
        except Exception as e:
            smtp_sent = False

    return {
        "success": True,
        "email": clean_email,
        "expires_in_seconds": 600,
        "mode": "SMTP_GMAIL" if smtp_sent else "DEVELOPER_SIMULATION",
        "simulated_code": raw_code if not smtp_sent else None,
        "message": f"Verification code sent to {clean_email}." if smtp_sent else f"Developer demo code generated for {clean_email}.",
    }


def verify_email_otp(to_email: str, entered_code: str) -> Dict[str, Any]:
    """Validate 6-digit OTP code against SQLite storage."""
    clean_email = to_email.strip().lower()
    code_clean = entered_code.strip()

    ensure_email_tables()

    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT code_hash, salt, expires_at FROM email_verifications WHERE email = ?",
            (clean_email,),
        ).fetchone()

        if not row:
            return {"valid": False, "error": "No pending verification code found for this email address."}

        code_hash, salt, expires_at = row["code_hash"], row["salt"], row["expires_at"]

        if time.time() > expires_at:
            return {"valid": False, "error": "Verification code has expired. Please request a new code."}

        expected_hash = hash_otp(code_clean, salt)
        if expected_hash != code_hash:
            return {"valid": False, "error": "Incorrect verification code. Please check and try again."}

        # Mark verified
        conn.execute(
            "UPDATE email_verifications SET verified = 1 WHERE email = ?",
            (clean_email,),
        )
        conn.commit()

    vip_token = f"CG-VIP-{clean_email[:4].upper()}-{int(time.time()) % 100000:05d}"
    return {
        "valid": True,
        "email": clean_email,
        "status": "VERIFIED",
        "vip_token": vip_token,
        "message": "Email successfully verified! VIP Autonomous Protection active.",
    }


def scan_email_spam_and_phishing(
    sender: str,
    subject: str,
    body: str,
    attachments: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Analyze incoming Gmail or corporate email for:
    1. Brand impersonation / sender domain spoofing
    2. Coercive psychological urgency triggers
    3. Malicious links & deceptive IP URLs
    4. Malicious executable/dropper attachments
    """
    ensure_email_tables()
    sender_clean = (sender or "").strip()
    subject_clean = (subject or "").strip()
    body_clean = (body or "").strip()
    attachments = attachments or []

    findings: List[str] = []
    risk_score = 0

    # 1. Sender Spoofing & Domain Typosquatting Analysis
    sender_domain = ""
    domain_match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender_clean)
    if domain_match:
        sender_domain = domain_match.group(1).lower()

    text_combined = f"{subject_clean} {body_clean}".lower()
    text_normalized = text_combined.translate(str.maketrans("013@", "olea"))
    sender_normalized = sender_clean.lower().translate(str.maketrans("013@", "olea"))

    # Check for brand impersonation
    for brand, trusted_domains in TRUSTED_BRAND_DOMAINS.items():
        if brand in text_normalized or brand in sender_normalized:
            # If email claims or mentions brand, does sender match legitimate brand domain?
            matches_trusted = any(sender_domain.endswith(td) for td in trusted_domains)
            if sender_domain and not matches_trusted:
                findings.append(f"BRAND_IMPERSONATION: Claims {brand.title()} identity but sender domain '{sender_domain}' is not an authorized official domain.")
                risk_score += 45

    # 2. Urgency & Coercive Phishing Keywords
    urgency_hits = []
    for pattern in URGENCY_TRIGGERS:
        if re.search(pattern, text_combined, re.IGNORECASE):
            urgency_hits.append(pattern)

    if urgency_hits:
        risk_score += min(35, len(urgency_hits) * 15)
        findings.append(f"PSYCHOLOGICAL_URGENCY: Found {len(urgency_hits)} coercive prompt pattern(s) forcing panic action (e.g., immediate suspension, unauthorized wire transfer).")

    # 3. Malicious Link Heuristics
    found_urls = URL_EXTRACT_RE.findall(f"{subject_clean} {body_clean}")
    suspicious_urls = []
    for u in found_urls:
        u_lower = u.lower()
        # IP address URL
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u_lower):
            suspicious_urls.append(f"Raw IP host: {u}")
            risk_score += 30
        # Suspicious TLDs commonly used in phishing campaigns
        elif any(u_lower.endswith(tld) or f"{tld}/" in u_lower for tld in [".cc", ".xyz", ".top", ".buzz", ".work", ".tk", ".cf"]):
            suspicious_urls.append(f"High-risk spam TLD: {u}")
            risk_score += 25

    if suspicious_urls:
        findings.append(f"DECEPTIVE_LINKS: Extracted {len(suspicious_urls)} deceptive or untrusted destination URL(s).")

    # 4. Dangerous Attachments
    malicious_files = []
    for att in attachments:
        if MALICIOUS_ATTACHMENT_RE.search(att):
            malicious_files.append(att)
            risk_score += 50

    if malicious_files:
        findings.append(f"DANGEROUS_ATTACHMENTS: Identified weaponized file extension(s): {', '.join(malicious_files)}")

    # Classify outcome
    risk_score = min(100, risk_score)
    if risk_score >= 60:
        threat_level = "CRITICAL_PHISHING"
        is_spam = True
        recommended_action = "QUARANTINE_AND_BLOCK_SENDER"
    elif risk_score >= 30:
        threat_level = "SUSPICIOUS_SPAM"
        is_spam = True
        recommended_action = "FLAG_FOR_AUDIT"
    else:
        threat_level = "SAFE"
        is_spam = False
        recommended_action = "DELIVER_NORMAL"

    # Record scan in SQLite
    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO email_spam_scans (sender, subject, threat_level, is_spam, heuristics, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (sender_clean, subject_clean, threat_level, 1 if is_spam else 0, "; ".join(findings), time.time()),
        )
        conn.commit()

    return {
        "sender": sender_clean,
        "subject": subject_clean,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "is_spam": is_spam,
        "findings": findings,
        "recommended_action": recommended_action,
        "scanned_links_count": len(found_urls),
        "attachments_analyzed": len(attachments),
    }
