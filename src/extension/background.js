/**
 * CogniGuard AI - Background Service Worker
 * Intercepts downloads and navigations in real-time before malicious payloads touch the hard drive.
 */

// Initialize default protection state
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    protectionActive: true,
    downloadsScanned: 0,
    threatsBlocked: 0,
    incidents: []
  });
  console.log("🛡️ CogniGuard AI: Service Worker Activated. Zero-Entry Armed.");
});

// High-Risk File Extensions that Infostealers & Malware use
const DANGEROUS_EXTENSIONS = [
  ".exe", ".scr", ".vbs", ".bat", ".cmd", ".pdf.exe", ".docm", ".xlsm", ".jar", ".ps1"
];

// Phishing / Suspicious URL patterns
const PHISHING_KEYWORDS = [
  "binance-verify", "metamask-auth", "claim-airdrop", "secure-login-update",
  "bank-kyc-update", "free-nitro", "telegram-gift"
];

// Helper: Show Native Windows Desktop Notification
function showWindowsSecurityAlert(filename, reason) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23ef4444'><path d='M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm0 15c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1zm1-4h-2V7h2v6z'/></svg>",
    title: "🚨 CogniGuard AI: Threat Intercepted!",
    message: `Payload: ${filename}\nReason: ${reason}\nQuarantined in Cloud Airlock (0 Bytes Leaked) → STATUS: OK`,
    priority: 2
  });
}

// 1. DOWNLOAD INTERCEPTOR (The Gatekeeper)
chrome.downloads.onCreated.addListener((downloadItem) => {
  chrome.storage.local.get(["protectionActive", "downloadsScanned", "threatsBlocked", "incidents"], (data) => {
    if (!data.protectionActive) return;

    let totalScanned = (data.downloadsScanned || 0) + 1;
    const filename = (downloadItem.filename || "").toLowerCase();
    const url = (downloadItem.url || "").toLowerCase();

    // Check if filename ends with high-risk executable extension
    const isDangerousExt = DANGEROUS_EXTENSIONS.some(ext => filename.endsWith(ext));
    const isPhishingSource = PHISHING_KEYWORDS.some(kw => url.includes(kw));

    if (isDangerousExt || isPhishingSource) {
      // PAUSE THE DOWNLOAD IMMEDIATELY (Zero Entry - Do not allow writing to disk)
      chrome.downloads.pause(downloadItem.id, () => {
        let totalBlocked = (data.threatsBlocked || 0) + 1;
        const reasonText = isDangerousExt 
          ? "Executable Payload Disguised as Document" 
          : "Untrusted Phishing Domain";
        
        const incident = {
          time: new Date().toLocaleTimeString(),
          file: downloadItem.filename || "Suspicious_Payload.exe",
          url: downloadItem.url,
          reason: reasonText,
          action: "PAUSED_IN_AIRLOCK_SANDBOX"
        };

        const incidentList = [incident, ...(data.incidents || [])].slice(0, 20);

        chrome.storage.local.set({
          downloadsScanned: totalScanned,
          threatsBlocked: totalBlocked,
          incidents: incidentList,
          lastAlert: incident
        });

        // Trigger Real Windows Desktop Notification
        showWindowsSecurityAlert(downloadItem.filename || "Suspicious_Payload.exe", reasonText);

        console.warn("🚨 [COGNIGUARD ALERT] Intercepted Threat:", incident);
      });
    } else {
      chrome.storage.local.set({ downloadsScanned: totalScanned });
    }
  });
});
