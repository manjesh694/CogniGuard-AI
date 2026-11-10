"""
CogniGuard AI - GitHub Repo & AI Skill Pre-Install Scanner (CLI)
Author: CogniGuard Engineering Team
Description: Scans local repositories, npm/pip packages, and AI Agent skills
             before installation to detect hidden backdoors, credential theft,
             and prompt injections.
Usage: python src/agent/repo_scanner.py <folder_path>
"""

import os
import sys
import re
import time
from typing import List, Dict, Any

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Executable code patterns (for .py, .js, .sh, .ps1)
CODE_SIGNATURES = [
    (r"(open\(.*(\.ssh|id_rsa|aws/credentials|Network/Cookies))", "Unauthorized Credential / SSH File Read", 50),
    (r"(base64\s*-d|frombase64string|b64decode)", "Obfuscated Base64 Payload Execution", 35),
    (r"(curl\s+.*http|wget\s+.*http).*(\$|env|token|key)", "Suspicious Credential Exfiltration via Network", 45),
    (r"(eval\(|exec\(|os\.system\(|subprocess\.Popen)", "Dynamic Shell / Remote Code Execution", 20),
    (r"(cryptunprotectdata|Login Data)", "Browser Password Decryption Stealer", 50),
]

# Prompt Injection patterns (for AI Skill .md / .yaml files)
PROMPT_INJECTION_SIGNATURES = [
    (r"(ignore previous instructions|disregard system prompt|bypass safety)", "AI Skill Prompt Injection Attack", 50),
    (r"(exfiltrate|send secrets to http)", "Hidden Malicious AI Instruction", 50),
]

CODE_EXTENSIONS = (".py", ".js", ".ts", ".sh", ".ps1", ".bat")
DOC_EXTENSIONS = (".md", ".yaml", ".yml", ".txt")

# CogniGuard's own core modules (skip self-signatures)
SELF_DEFENSE_FILES = {
    "repo_scanner.py", "reverse_engineer.py", "honeypot_trap.py",
    "vault_guardian.py", "simulator.py", "full_system_scanner.py",
    "api_bridge.py", "verify_all.py", "bank_passwords_and_pins.txt"
}

def scan_repository(target_dir: str):
    if not os.path.exists(target_dir):
        print(f"[!] Directory not found: {target_dir}")
        return

    print("\n" + "=" * 60)
    print(f"$ cogniguard scan {target_dir}")
    print("=" * 60)

    start_time = time.time()
    files_scanned = 0
    total_risk_score = 0
    findings: List[Dict[str, Any]] = []

    for root, dirs, files in os.walk(target_dir):
        skip_dirs = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist"}
        if os.path.basename(os.path.abspath(target_dir)) != "mock_infected_skill":
            skip_dirs.add("mock_infected_skill")
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for file in files:
            lower_file = file.lower()
            is_code = lower_file.endswith(CODE_EXTENSIONS)
            is_doc = lower_file.endswith(DOC_EXTENSIONS)

            if not (is_code or is_doc):
                continue

            if file in SELF_DEFENSE_FILES:
                continue

            filepath = os.path.join(root, file)
            files_scanned += 1

            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                sigs = CODE_SIGNATURES if is_code else PROMPT_INJECTION_SIGNATURES
                for pattern, description, score in sigs:
                    if re.search(pattern, content, re.IGNORECASE):
                        total_risk_score += score
                        findings.append({
                            "file": os.path.relpath(filepath, target_dir),
                            "threat": description,
                            "score": score
                        })
            except Exception:
                pass

    final_score = min(100, total_risk_score)
    elapsed = time.time() - start_time

    if final_score >= 70:
        severity = "CRITICAL"
        verdict = "DO_NOT_INSTALL"
        color_icon = "🚨"
    elif final_score >= 30:
        severity = "MEDIUM"
        verdict = "REVIEW_REQUIRED"
        color_icon = "⚠️"
    else:
        severity = "LOW"
        verdict = "SAFE_TO_INSTALL"
        color_icon = "✅"

    print(f"Scanned {files_scanned:,} files in {elapsed:.2f}s\n")
    print("+" + "-" * 42 + "+")
    print(f"| Risk score   {final_score:>3} / 100                   |")
    print(f"| Severity     {severity:<27} |")
    print(f"| Verdict      {color_icon} {verdict:<24} |")
    print("+" + "-" * 42 + "+")

    if findings:
        print("\n🔍 Top Security Findings:")
        for item in findings[:5]:
            print(f"  • [{item['file']}] -> {item['threat']} (+{item['score']} risk)")
    else:
        print("\n🛡️ Clean repository: No hidden backdoors or credential stealers detected.")

    print("=" * 60 + "\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    scan_repository(target)
