# CogniGuard AI — Go-To-Market Launch Playbook

## 1. Live Web & Funnel Checklist
* **Landing Page:** https://manjesh694.github.io/CogniGuard-AI/
* **Interactive Repo & AI-Skill Demo:** https://manjesh694.github.io/CogniGuard-AI/demo_portal.html
* **B2B SOC Console:** https://manjesh694.github.io/CogniGuard-AI/dashboard.html
* **Investor Pitch Deck:** https://manjesh694.github.io/CogniGuard-AI/pitch_deck.html
* **Privacy Policy:** https://manjesh694.github.io/CogniGuard-AI/privacy.html

Verify before driving traffic:
1. Click **Start 14-Day Trial** and **Contact Enterprise Sales** on the landing page to confirm the onboarding modal issues a trial key and opens a pre-filled enterprise inquiry.
2. Click **Download Free Extension (.ZIP)** to confirm `cogniguard-ai-v1.0.3.zip` downloads cleanly.

---

## 2. Chrome Web Store Submission (15 Minutes)
1. Open the Chrome Web Store Developer Dashboard.
2. Upload **`dist/cogniguard-ai-v1.0.3.zip`** (Manifest V3, version `1.0.3`).
3. Copy/paste Store Metadata, Description, and Permissions Justifications directly from [`docs/CHROME_STORE_LISTING.md`](./CHROME_STORE_LISTING.md):
   * **Official Website URL:** `https://manjesh694.github.io/CogniGuard-AI/`
   * **Privacy Policy URL:** `https://manjesh694.github.io/CogniGuard-AI/privacy.html`
   * **Support Contact:** `manjesh694@gmail.com`

---

## 3. Viral Developer Video Launch (30-Second PLG Hook)
Follow [`docs/VIRAL_VIDEO_SCRIPT.md`](./VIRAL_VIDEO_SCRIPT.md) and record:
```powershell
cogniguard scan tests/mock_infected_skill
```
Publish as YouTube Short, Instagram Reel, and LinkedIn Video with the pinned comment linking to:
* Landing Page: `https://manjesh694.github.io/CogniGuard-AI/`
* 60-Second Interactive Demo: `https://manjesh694.github.io/CogniGuard-AI/demo_portal.html`

---

## 4. B2B Pilot & Telemetry Operations
Run the local telemetry & security bridge during live customer demos:
```powershell
cogniguard bridge
```
Inspect live conversion and threat metrics at:
* `GET http://127.0.0.1:8765/api/v1/telemetry/summary`
* `GET http://127.0.0.1:8765/api/v1/leads`
* `GET http://127.0.0.1:8765/api/v1/logs`
