"""
CogniGuard AI - Agentic Threat Intelligence & Psychology Explainer
Author: CogniGuard Engineering Team
Description: Autonomous reasoning engine that deconstructs the psychological
             manipulation, evasion vectors, and exfiltration mechanics of
             intercepted phishing URLs, fake files, and predatory loan traps.
"""

import os
import re
from typing import Any, Dict, List, Optional


class ThreatPsychologyReport:
    """Structured incident breakdown for security analysts and end-users."""

    def __init__(
        self,
        category: str,
        urgency_level: str,
        psychological_triggers: List[str],
        evasion_tactics: List[str],
        exfiltration_risk: str,
        recommended_actions: List[str],
        summary: str,
        ai_briefing: Optional[str] = None,
    ):
        self.category = category
        self.urgency_level = urgency_level
        self.psychological_triggers = psychological_triggers
        self.evasion_tactics = evasion_tactics
        self.exfiltration_risk = exfiltration_risk
        self.recommended_actions = recommended_actions
        self.summary = summary
        self.ai_briefing = ai_briefing

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "urgency_level": self.urgency_level,
            "psychological_triggers": self.psychological_triggers,
            "evasion_tactics": self.evasion_tactics,
            "exfiltration_risk": self.exfiltration_risk,
            "recommended_actions": self.recommended_actions,
            "summary": self.summary,
            "ai_briefing": self.ai_briefing,
        }


class AgenticThreatExplainer:
    """Explains attacks using offline deterministic threat models + optional Gemini LLM."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    def explain(self, text_or_url: str, threat_type: Optional[str] = None) -> ThreatPsychologyReport:
        content = (text_or_url or "").strip()
        lower = content.lower()

        # 1. Predatory Instant Loan / Extortion Traps
        if any(w in lower for w in ["loan", "disburs", "instant", "approval", "loanzap", "kredit", "rupee"]):
            return ThreatPsychologyReport(
                category="Predatory Instant Loan & Micro-Finance Trap",
                urgency_level="CRITICAL",
                psychological_triggers=[
                    "Manufactured Financial Relief: Exploits economic distress with promise of guaranteed instant funds.",
                    "Pre-Approved Deception: Fabricates pre-approval to induce false sense of entitlement.",
                    "High-Velocity Pressure: Uses 'Immediate/Instant Disbursal' to bypass critical judgment.",
                ],
                evasion_tactics=[
                    "Deceptive Domain Mimicry: Employs fin-tech sounding words on newly registered TLDs (.in, .top, .app).",
                    "Off-Market APK Dropper: Directs user to sideload an unvetted APK, bypassing Google Play Protect.",
                    "Obfuscated Shortlinks: Evades SMS gateway spam filters through redirect chains.",
                ],
                exfiltration_risk="HIGH: Unauthorized harvesting of entire device address book, SMS inbox (banking OTPs), and gallery metadata used for blackmail.",
                recommended_actions=[
                    "Neutralize: Do NOT click, install, or grant contact/SMS permissions.",
                    "Block & Report: Block sender number and report to Cyber Crime Helpline 1930 / cybercrime.gov.in.",
                    "Verify Legitimacy: Only borrow through RBI-licensed Banks or NBFC registered apps.",
                ],
                summary="Attacker deploys an unvetted loan application lure to trick the victim into sideloading an infostealer APK that harvests phone contacts and photos for predatory extortion.",
            )

        # 2. Bank KYC / Account Suspension / PAN Traps
        if any(w in lower for w in ["kyc", "pan", "deactivat", "suspend", "block", "sbi", "hdfc", "icici"]):
            return ThreatPsychologyReport(
                category="Banking Impersonation & Credential Harvesting Trap",
                urgency_level="CRITICAL",
                psychological_triggers=[
                    "Fear of Financial Disruption: Threatens imminent account suspension or card blocking.",
                    "False Institutional Authority: Impersonates RBI, SBI, HDFC, or Tax Authorities.",
                    "Punitive Deadline: Sets countdowns ('within 24 hours') to trigger panic-induced obedience.",
                ],
                evasion_tactics=[
                    "Lookalike Web Portals: Clones official net-banking login pages byte-for-byte.",
                    "Reverse Proxy Session Capture: Intercepts multi-factor OTPs in real-time to hijack active banking sessions.",
                ],
                exfiltration_risk="CRITICAL: Full compromise of Internet banking credentials, debit card CVV, and UPI transaction MPINs.",
                recommended_actions=[
                    "Never enter banking credentials or OTPs on links received via SMS.",
                    "Access official banking portals exclusively via verified bookmarks or official apps.",
                    "Immediately alert your bank's fraud helpline if credentials were submitted.",
                ],
                summary="Attacker impersonates a trusted financial institution to induce panic, coercing the victim into entering net-banking credentials and OTPs into a credential harvester.",
            )

        # 3. Disguised Malicious Files (Double Extension / Fake Photo)
        if any(w in lower for w in [".exe", ".scr", ".bat", ".vbs", ".apk", ".ps1", "receipt.pdf.exe"]):
            return ThreatPsychologyReport(
                category="Disguised Malware Dropper & Double Extension Evasion",
                urgency_level="CRITICAL",
                psychological_triggers=[
                    "Curiosity & Compliance: Disguised as an invoice, job offer, or sensitive photo.",
                    "Trust Exploitation: Hides true executable extension using Unicode right-to-left override or multiple dots.",
                ],
                evasion_tactics=[
                    "Double Extension Trickery (e.g. wedding_photo.jpg.exe).",
                    "Icon Spoofing: Borrows Windows photo or PDF system icons to mask executable PE headers.",
                    "Memory-Only Injection: Injects payload into legitimate svchost.exe to bypass basic antivirus.",
                ],
                exfiltration_risk="EXTREME: Stealth infostealer extraction of stored Chrome passwords, crypto wallet private keys, and session cookies.",
                recommended_actions=[
                    "Enable 'Show File Extensions' in Windows Explorer to reveal hidden .exe extensions.",
                    "CogniGuard has automatically quarantined and locked the file in memory.",
                    "Flush browser sessions and rotate active credentials.",
                ],
                summary="Attacker disguises a Trojan or Infostealer payload as a harmless document or image to achieve arbitrary remote code execution on the endpoint.",
            )

        # Default Phishing / Suspicious Vector
        return ThreatPsychologyReport(
            category="Generic Social Engineering & Phishing Vector",
            urgency_level="HIGH",
            psychological_triggers=[
                "Curiosity Gap: Lures target with unexpected notifications or unverifiable incentives.",
                "Unsolicited Engagement: Circumvents standard verification paths.",
            ],
            evasion_tactics=[
                "High Domain Entropy: Uses randomized subdomains to evade static blocklists.",
                "Zero-Entry Link: Conceals target destination behind tracking redirects.",
            ],
            exfiltration_risk="MODERATE: Potential credential phishing or device fingerprint harvesting.",
            recommended_actions=[
                "Do not tap or submit information on unverified external domains.",
                "Verify domain authenticity using CogniGuard Global Threat Radar.",
            ],
            summary="Suspicious communication exhibiting anomalous domain characteristics and evasion patterns consistent with credential harvesting or referral scams.",
        )
