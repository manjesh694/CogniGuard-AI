"""
CogniGuard AI - Shared Security Heuristics & File Inspection Helpers
Author: CogniGuard Engineering Team
Description: Single source of truth for dangerous payload extensions,
             disguised PE header detection, and filename risk evaluation.
"""

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
    ".ps1",
) + DOUBLE_EXTENSIONS

DISGUISED_DOC_EXTENSIONS = (".pdf", ".jpg", ".png", ".txt", ".docx")


def is_disguised_executable(filepath: str) -> bool:
    """Return True if a document/image file begins with a Windows PE (MZ) header."""
    try:
        if os.path.isfile(filepath) and os.path.getsize(filepath) > 64:
            lower_name = filepath.lower()
            if lower_name.endswith(DISGUISED_DOC_EXTENSIONS):
                with open(filepath, "rb") as f:
                    return f.read(2) == PE_MAGIC_BYTES
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
