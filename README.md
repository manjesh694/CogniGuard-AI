# CogniGuard AI 🛡️
> **Zero Entry. Zero Breaches. Autonomous Pre-Execution Cloud Defense.**

CogniGuard AI is an autonomous, agentic cybersecurity platform designed to protect remote IT workers, developers, and everyday consumers against the modern #1 attack vector: **human-layer credential theft, session hijacking, malicious AI skills, and disguised payloads.**

* **Live Website:** https://manjesh694.github.io/CogniGuard-AI/
* **Interactive Scanner Demo:** https://manjesh694.github.io/CogniGuard-AI/demo_portal.html
* **B2B SOC Console:** https://manjesh694.github.io/CogniGuard-AI/dashboard.html
* **Investor Pitch Deck:** https://manjesh694.github.io/CogniGuard-AI/pitch_deck.html

---

## Architecture Overview

```
                      [ User Laptop / Endpoint ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
[ Chrome Extension v1.0.3 ]                        [ Desktop Agent & CLI ]
(Download & Link Interceptor)                     (Repo Scanner, 24/7 Daemon & Vault)
         │                                                 │
         └────────────────────────┬────────────────────────┘
                                  │ (REST / Telemetry Bridge :8765)
                                  ▼
                    [ CogniGuard Security Engine ]
    ┌───────────────────────────────────────────────────────────┐
    │ • Pre-Install Repo & AI-Skill Scanner (`cogniguard scan`) │
    │ • 24/7 Downloads & Honeypot Watcher (`cogniguard daemon`) │
    │ • Zero-Trust Credential Shield & Disguised-PE Inspector   │
    └─────────────────────────────┬─────────────────────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
       [ Consumer Mobile App ]          [ Enterprise SOC Console ]
       (Real-Time Push Alerts)          (Fleet Telemetry & Audits)
```

---

## Core Modules

* **`src/agent/cli.py`**: Unified `cogniguard` CLI (`scan`, `daemon`, `bridge`, `system-scan`).
* **`src/agent/repo_scanner.py`**: Pre-install scanner detecting hidden credential theft, obfuscated payloads, and AI skill prompt injections.
* **`src/agent/guardian_daemon_24x7.py`**: 24/7 background watcher monitoring Downloads and the honeypot bait file (`bank_passwords_and_pins.txt`).
* **`src/agent/api_bridge.py`**: FastAPI bridge serving download inspection, repo scanning, lead capture, and SOC telemetry endpoints.
* **`src/agent/vault_guardian.py` & `src/agent/full_system_scanner.py`**: Credential vault tripwires and disguised PE-header disk auditor.
* **`src/extension/`**: Chrome Manifest V3 extension (`v1.0.3`), pre-packaged in `dist/cogniguard-ai-v1.0.3.zip` and `docs/cogniguard-ai-v1.0.3.zip`.

---

## Getting Started

### 1. Install Dependencies & `cogniguard` CLI
* Python 3.10+

```bash
pip install -r requirements.txt
pip install -e .
```

### 2. Scan a Repository or AI Skill Before Installing
```bash
cogniguard scan tests/mock_infected_skill
```

### 3. Start the 24/7 Guardian Daemon or Local API Bridge
```bash
cogniguard daemon
cogniguard bridge
```

### 4. Run Verification Tests
```bash
python tests/verify_all.py
pytest -v
```
