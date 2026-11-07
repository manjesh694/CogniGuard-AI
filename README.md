# CogniGuard AI 🛡️
> **Zero Entry. Zero Breaches. Autonomous Pre-Execution Cloud Defense.**

CogniGuard AI is an autonomous, agentic cybersecurity platform designed to protect remote IT workers, developers, and everyday consumers against the modern #1 attack vector: **human-layer credential theft, session hijacking, and malicious payloads.**

---

## Architecture Overview

```
                      [ User Laptop / Endpoint ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
[ Browser Extension ]                             [ Desktop Agent ]
(Download & Link Interceptor)                     (Vault & Process Guardian)
         │                                                 │
         └────────────────────────┬────────────────────────┘
                                  │ (Encrypted gRPC / WebSocket)
                                  ▼
                    [ CogniGuard Cloud Engine ]
    ┌───────────────────────────────────────────────────────────┐
    │ • Micro-Sandbox Detonation (Disposable Container Cluster) │
    │ • Heuristic AI Threat Engine (Behavioral ML Scoring)      │
    │ • Zero-Trust Credential Shield (Tripwire Vault)          │
    └─────────────────────────────┬─────────────────────────────┘
                                  │
                  ┌───────────────┴───────────────┐
                  ▼                               ▼
       [ Consumer Mobile App ]          [ Enterprise IT Console ]
       (Real-Time Push Alerts)          (Fleet Management & Logs)
```

---

## Core Modules

* **`src/agent/vault_guardian.py`**: The core autonomous watcher that monitors sensitive credential locations (`.env`, SSH keys, browser cookies) and intercepts unauthorized access attempts in real time.
* **`src/agent/simulator.py`**: Interactive simulation script to test intrusion detection and automated containment.
* **`src/web/dashboard.html`**: Sleek, high-performance security operations center (SOC) dashboard.

---

## Getting Started

### 1. Requirements
* Python 3.10+
* Any modern web browser

### 2. Run the Security Simulation
```bash
python src/agent/simulator.py
```

### 3. Open the Security Dashboard
Double-click `src/web/dashboard.html` to open the live visual operations console in your browser.
