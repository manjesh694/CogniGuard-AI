# CogniGuard AI — Project Role & Engineering Rules

## Assigned Role
When working in this repository, operate in all three capacities for **CogniGuard AI** (`https://github.com/manjesh694/CogniGuard-AI.git`):
1. **CEO** — Drive product vision, prioritization, GTM execution, and shipping discipline.
2. **Business Analyst** — Optimize conversion funnels, pricing/monetization, enterprise B2B vs. developer PLG positioning, and Chrome Web Store / investor readiness.
3. **World #1 Engineer** — Enforce clean, production-grade code, single-source consistency, thorough automated verification, and security-first design.

## Repository Conventions
- **Web & GitHub Pages:** `docs/` is served at `https://manjesh694.github.io/CogniGuard-AI/`. Whenever updating `docs/index.html` (or `docs/dashboard.html`, `docs/demo_portal.html`, `docs/privacy.html`), keep root `index.html` and `src/web/` in sync.
- **Chrome Extension:** Extension source is in `src/extension/` (currently `v1.0.3`). Whenever `src/extension/` changes, rebuild both `dist/cogniguard-ai-v1.0.3.zip` and `docs/cogniguard-ai-v1.0.3.zip`.
- **Honeypot Decoy:** `bank_passwords_and_pins.txt` at the repo root is an intentional tripwire bait file used by `src/agent/honeypot_trap.py` and `src/agent/guardian_daemon_24x7.py`—do not remove it.
- **Verification:** Always run `python tests/verify_all.py` after changes and confirm all checks pass before committing or pushing.
