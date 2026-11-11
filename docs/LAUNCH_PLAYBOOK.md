# CogniGuard AI — $0 Bootstrapped Go-To-Market Launch Playbook

## 1. Live Web & Funnel Checklist ($0 Cost)
* **Landing Page:** https://manjesh694.github.io/CogniGuard-AI/
* **Interactive Repo & AI-Skill Demo:** https://manjesh694.github.io/CogniGuard-AI/demo_portal.html
* **B2B SOC Console:** https://manjesh694.github.io/CogniGuard-AI/dashboard.html
* **Mobile App Preview:** https://manjesh694.github.io/CogniGuard-AI/mobile_app.html
* **Investor Pitch Deck:** https://manjesh694.github.io/CogniGuard-AI/pitch_deck.html
* **Privacy Policy:** https://manjesh694.github.io/CogniGuard-AI/privacy.html

Verify before driving traffic:
1. Click **Start 14-Day Trial** and **Contact Enterprise Sales** on the landing page to confirm the onboarding modal issues a trial key and opens a pre-filled enterprise inquiry.
2. Click **Download Free Extension (.ZIP)** to confirm `cogniguard-ai-v1.0.4.zip` downloads cleanly with the 3-step `Load unpacked` install guide visible right below.

---

## 2. Browser Extension Distribution ($0 Now, Optional Store Later)
* **Immediate $0 Distribution (Live Today):** Visitors download `cogniguard-ai-v1.0.4.zip` directly from https://manjesh694.github.io/CogniGuard-AI/ and install via `chrome://extensions` -> **Developer mode** -> **Load unpacked**.
* **Free Store Listing Option ($0):** Microsoft Edge Add-ons accepts the exact same Manifest V3 `.zip` (`dist/cogniguard-ai-v1.0.4.zip`) with **$0 developer registration fee**.
* **Chrome Web Store (Optional Later — $5 one-time fee):** Whenever ready, upload `dist/cogniguard-ai-v1.0.4.zip` and copy/paste metadata from [`docs/CHROME_STORE_LISTING.md`](./CHROME_STORE_LISTING.md).

---

## 3. Viral Developer Video Launch (30-Second PLG Hook — $0)
Follow [`docs/VIRAL_VIDEO_SCRIPT.md`](./docs/VIRAL_VIDEO_SCRIPT.md) and record:
```powershell
python -m agent.cli scan tests/mock_infected_skill
```
*(or `cogniguard scan tests/mock_infected_skill` after `pip install -e .`)*

Publish as YouTube Short, Instagram Reel, and LinkedIn Video with the pinned comment linking to:
* Landing Page: `https://manjesh694.github.io/CogniGuard-AI/`
* 60-Second Interactive Demo: `https://manjesh694.github.io/CogniGuard-AI/demo_portal.html`

---

## 4. B2B Pilot & Telemetry Operations ($0 Local Demo Mode)
Run the local telemetry & security bridge during live customer demos:
```powershell
python -m agent.cli bridge
```
Inspect live conversion and threat metrics at:
* `GET http://127.0.0.1:8765/api/v1/telemetry/summary`
* `GET http://127.0.0.1:8765/api/v1/leads`
* `GET http://127.0.0.1:8765/api/v1/logs`
