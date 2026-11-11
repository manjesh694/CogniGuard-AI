# CogniGuard AI 🛡️
> **Zero Entry. Zero Breaches. Autonomous Pre-Execution Cloud Defense.**

CogniGuard AI is an autonomous, agentic cybersecurity platform designed to protect remote IT workers, developers, and everyday consumers against the modern #1 attack vector: **human-layer credential theft, session hijacking, malicious AI skills, and disguised payloads.**

* **Live Website:** https://manjesh694.github.io/CogniGuard-AI/
* **Interactive Scanner Demo & Video:** https://manjesh694.github.io/CogniGuard-AI/demo_portal.html ([Watch 20s Demo MP4](https://manjesh694.github.io/CogniGuard-AI/cogniguard-demo-short.mp4))
* **B2B SOC Console:** https://manjesh694.github.io/CogniGuard-AI/dashboard.html
* **Investor Pitch Deck:** https://manjesh694.github.io/CogniGuard-AI/pitch_deck.html

---

## Architecture Overview

```
                      [ User Laptop / Endpoint ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
[ Chrome Extension v1.0.4 ]                        [ Desktop Agent & CLI ]
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

* **`src/agent/cli.py`**: Unified `cogniguard` CLI (`scan [--format text|json|sarif]`, `daemon`, `bridge`, `system-scan`, `quarantine`, `process-audit`).
* **`src/agent/repo_scanner.py`**: Pre-install scanner for local folders and `https://github.com/...` URLs using regex + Python AST & Shannon entropy analysis + SARIF v2.1.0 output.
* **`src/agent/guardian_daemon_24x7.py` & `src/agent/quarantine.py`**: 24/7 Downloads & Honeypot watcher that automatically hashes (`SHA-256`) and isolates flagged payloads into `.quarantine/`.
* **`src/agent/storage.py`**: Thread-safe SQLite WAL store for audit logs, quarantine records, leads, and alert settings.
* **`src/agent/api_bridge.py`**: Hardened FastAPI server (`127.0.0.1:8765` or `$PORT` via `render.yaml`/`Dockerfile`) with rate limiting, `X-API-Key` auth, CSV/JSON audit export, reverse engineering, live `psutil` process auditing, and Slack/Discord/SIEM webhook alerts.
* **`src/agent/vault_guardian.py` & `src/agent/full_system_scanner.py`**: Live `psutil` OS process auditor, credential vault tripwires, and disguised PE-header disk auditor.
* **`src/extension/`**: Chrome Manifest V3 extension (`v1.0.4`), pre-packaged in `dist/cogniguard-ai-v1.0.4.zip` and `docs/cogniguard-ai-v1.0.4.zip`.

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
cogniguard scan https://github.com/manjesh694/CogniGuard-AI --format sarif
```

### 3. Start the 24/7 Guardian Daemon, Process Audit, or API Bridge
```bash
cogniguard daemon
cogniguard process-audit
cogniguard bridge
```

### 4. Install the Free Browser Extension (20 Seconds, No Store Required)
1. Download [`docs/cogniguard-ai-v1.0.4.zip`](https://manjesh694.github.io/CogniGuard-AI/cogniguard-ai-v1.0.4.zip) and unzip it.
2. Open `chrome://extensions` (or `edge://extensions`) and enable **Developer mode**.
3. Click **Load unpacked** and select the unzipped folder.

### 5. Use in GitHub Actions CI (`action.yml`)
```yaml
- uses: manjesh694/CogniGuard-AI@main
  with:
    target: "."
    strict: "true"
    format: "sarif"
```

### 6. Run Verification Tests & Sync Release Assets
```bash
python scripts/build_release.py
python tests/verify_all.py
pytest -v
```

---

## CLI & API Quick Reference

| Command | Purpose |
| :--- | :--- |
| `cogniguard scan <path_or_github_url> [--format text\|json\|sarif] [--strict]` | Pre-install repo, AI-skill, AST, secret-leak & container scan |
| `cogniguard daemon` | 24/7 Downloads & Honeypot watcher with SHA-256 quarantine |
| `cogniguard bridge` | Start FastAPI server (`:8765`) for extension, demo, & SOC console |
| `cogniguard process-audit [--json]` | Inspect live OS processes via `psutil` |
| `cogniguard quarantine list\|restore\|shred` | Manage isolated files in `.quarantine/` |
| `cogniguard ioc add\|list\|remove` | Manage fleet SHA-256 Threat Intelligence blocklist |
| `cogniguard install-hook [repo_path]` | Install `.git/hooks/pre-commit` security gate |
| `cogniguard doctor [--json]` | Run system, dependency, DB, & security posture check |
