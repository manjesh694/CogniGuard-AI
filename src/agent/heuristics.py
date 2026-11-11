"""
CogniGuard AI - Shared Security Heuristics & File Inspection Helpers
Author: CogniGuard Engineering Team
Description: Single source of truth for dangerous payload extensions,
             disguised PE header detection, and filename risk evaluation.
"""

import hashlib
import os
from typing import Any, Dict

PE_MAGIC_BYTES = b"MZ"

DOUBLE_EXTENSIONS = (
    ".pdf.exe",
    ".doc.exe",
    ".docx.exe",
    ".jpg.exe",
    ".png.exe",
    ".txt.exe",
    ".zip.exe",
)

DANGEROUS_EXTENSIONS = (
    ".exe",
    ".scr",
    ".vbs",
    ".bat",
    ".cmd",
    ".docm",
    ".xlsm",
    ".jar",
    ".ps1",
) + DOUBLE_EXTENSIONS

DISGUISED_DOC_EXTENSIONS = (".pdf", ".jpg", ".png", ".txt", ".docx")

PHISHING_KEYWORDS = (
    "binance-verify",
    "metamask-auth",
    "claim-airdrop",
    "secure-login-update",
    "bank-kyc-update",
    "free-nitro",
    "telegram-gift",
    "whatsapp-verify",
    "facebook-security",
    "instagram-badge",
    "linkedin-talent-verify",
)


def is_pe_magic_bytes(raw_bytes: bytes) -> bool:
    """Return True if raw bytes begin with the Windows PE (MZ) signature."""
    return len(raw_bytes) >= 2 and raw_bytes[:2] == PE_MAGIC_BYTES


def is_disguised_executable(filepath: str) -> bool:
    """Return True if a document/image file begins with a Windows PE (MZ) header."""
    try:
        if os.path.isfile(filepath) and os.path.getsize(filepath) > 64:
            lower_name = filepath.lower()
            if lower_name.endswith(DISGUISED_DOC_EXTENSIONS):
                with open(filepath, "rb") as f:
                    return is_pe_magic_bytes(f.read(2))
    except (PermissionError, OSError):
        pass
    return False


def evaluate_filename_risk(filename: str) -> Dict[str, Any]:
    """Evaluate download filename risk using shared extension & disguise rules."""
    clean_name = filename.strip().lower()
    is_double_ext = clean_name.endswith(DOUBLE_EXTENSIONS)
    is_dangerous = clean_name.endswith(DANGEROUS_EXTENSIONS)

    if is_double_ext:
        return {
            "verdict": "INTRUSION_DETECTED",
            "threat_score": 0.99,
            "action_taken": "QUARANTINE_IN_AIRLOCK",
            "reason": "Executable payload disguised with double extension",
        }
    if is_dangerous:
        return {
            "verdict": "INTRUSION_DETECTED",
            "threat_score": 0.96,
            "action_taken": "QUARANTINE_IN_AIRLOCK",
            "reason": "High-risk executable or script download intercepted",
        }
    return {
        "verdict": "SAFE",
        "threat_score": 0.04,
        "action_taken": "ALLOW",
        "reason": "Clean verified file",
    }


def evaluate_download_risk(filename: str, source_url: str = "") -> Dict[str, Any]:
    """Evaluate both filename heuristics and source URL phishing indicators."""
    result = evaluate_filename_risk(filename)
    if result["verdict"] != "SAFE":
        return result

    lower_url = (source_url or "").lower()
    matched_kw = next((kw for kw in PHISHING_KEYWORDS if kw in lower_url), None)
    if matched_kw:
        return {
            "verdict": "INTRUSION_DETECTED",
            "threat_score": 0.94,
            "action_taken": "QUARANTINE_IN_AIRLOCK",
            "reason": f"Untrusted phishing download source ({matched_kw})",
        }
    return result


def evaluate_bytes_risk(raw_bytes: bytes, filename: str, source_url: str = "") -> Dict[str, Any]:
    """Evaluate file bytes (PE disguise + SHA-256) alongside filename & URL checks."""
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    lower_name = filename.strip().lower()
    if lower_name.endswith(DISGUISED_DOC_EXTENSIONS) and is_pe_magic_bytes(raw_bytes):
        return {
            "verdict": "INTRUSION_DETECTED",
            "threat_score": 0.99,
            "action_taken": "QUARANTINE_IN_AIRLOCK",
            "reason": "Disguised Windows executable (MZ header) inside document",
            "sha256": sha256,
        }

    result = evaluate_download_risk(filename, source_url)
    result["sha256"] = sha256
    return result
