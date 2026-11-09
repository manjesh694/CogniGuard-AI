# CogniGuard AI — Chrome Web Store Submission Kit 🚀

This document contains the exact information to copy & paste into the **Google Chrome Web Store Developer Dashboard** to get your extension approved and published.

---

## 1. Store Metadata

* **Extension Name:** `CogniGuard AI - Zero-Entry Cyber Guardian`
* **Short Description (132 chars max):**  
  `Autonomous Zero-Entry AI Agent protecting laptops against infostealer trojans, credential theft, and disguised malicious downloads.`
* **Category:** `Privacy and security`
* **Visibility:** `Public` (or `Unlisted` during initial review)
* **Price:** `Free`
* **Official Website URL:** `https://manjesh694.github.io/CogniGuard-AI/src/web/`
* **Privacy Policy URL:** `https://manjesh694.github.io/CogniGuard-AI/src/web/privacy.html`
* **Support Contact:** `manjesh694@gmail.com`

---

## 2. Detailed Store Description (Copy & Paste)

```markdown
🛡️ Zero Entry. Zero Breaches. Autonomous Pre-Execution Cloud Defense.

Global cybercrime damages have crossed $10.5 Trillion. Modern hackers no longer focus on complex code exploits—they compromise human endpoints, employee laptops, and remote workers using disguised PDFs (.pdf.exe), deceptive recruiter contracts, and infostealer malware designed to dump browser session cookies and passwords in seconds.

Traditional antivirus software scans files AFTER they are downloaded to your disk. By then, it is often too late.

CogniGuard AI introduces true Zero-Entry Protection:

✨ KEY FEATURES:

1. ☁️ Pre-Execution Cloud Airlock
Incoming executable downloads (.exe, .scr, .vbs) are paused in memory before they ever touch your physical hard drive. Threats are isolated and evaluated before execution.

2. 🔒 Credential & Cookie Vault Shield
Protects your Google Chrome session tokens, AWS cloud keys, and developer secrets from unauthorized extraction by background malware.

3. 🎙️ Autonomous AI Voice & Cyber Audio Alerts
Hear instant audio verification when a threat is neutralized: "Warning. Threat detected. Quarantined in cloud airlock. 0 bytes leaked. System is secure."

4. 🔔 Smart Native Windows Notifications
Rate-limited, deduplicated desktop alerts inform you of blocked attacks without screen clutter.

5. ✅ One-Click "Allow & Resume"
Need to install a legitimate developer tool like Git or Node.js? Easily whitelist and resume trusted downloads with a single click.

🔒 PRIVACY & ZERO-DATA GUARANTEE:
CogniGuard AI does NOT harvest, sell, or track your personal browsing history, passwords, or personal documents. All heuristic analysis runs locally or in disposable sandbox containers.

Join the zero-entry movement today. Install CogniGuard AI and browse with complete peace of mind.
```

---

## 3. Chrome Web Store Permissions Justifications (Required by Google)

* **`downloads`:**  
  *Justification:* "Required to monitor and pause untrusted executable downloads (.exe, .vbs, .scr) in memory before they write to the user's local disk, preventing infostealer infection."
* **`storage`:**  
  *Justification:* "Used to save local security counters (downloads scanned, threats blocked) and user whitelist preferences locally on the client."
* **`webNavigation`:**  
  *Justification:* "Used to detect known deceptive phishing domains and fake login redirects before credentials can be entered."
* **`notifications`:**  
  *Justification:* "Used to display native system notifications when an intrusion attempt or malicious payload is intercepted."

---

## 4. Package File to Upload

* **Upload File:** `dist/cogniguard-ai-v1.0.2.zip` (Pre-packaged and ready in your project directory!)
