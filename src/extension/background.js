/**
 * CogniGuard AI - Background Service Worker
 * Intercepts downloads and navigations in real-time with smart deduplication and rate-limiting.
 */

// Initialize default protection state
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    protectionActive: true,
    downloadsScanned: 0,
    threatsBlocked: 0,
    incidents: [],
    lastPausedDownloadId: null
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

// Cache to prevent duplicate notifications for the same download
const processedDownloadIds = new Set();
let lastAlertTimestamp = 0;

// Helper: Show Single, Rate-Limited Native Windows Desktop Notification
function showWindowsSecurityAlert(filename, reason) {
  const now = Date.now();
  // Rate-limit: Do not fire more than 1 notification every 4 seconds
  if (now - lastAlertTimestamp < 4000) {
    return;
  }
  lastAlertTimestamp = now;

  // Use a fixed notification ID 'cogniguard_alert' so Chrome REPLACES the old notification
  // instead of stacking non-stop popups on the screen!
  chrome.notifications.clear("cogniguard_alert", () => {
    chrome.notifications.create("cogniguard_alert", {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "🛡️ CogniGuard AI: Threat Intercepted!",
      message: `Paused: ${filename}\nQuarantined in Cloud Airlock.\nOpen CogniGuard to Allow if trusted.`,
      priority: 1
    });
  });
}

// 1. DOWNLOAD INTERCEPTOR (The Gatekeeper)
chrome.downloads.onCreated.addListener((downloadItem) => {
  // Prevent duplicate triggers for the same download ID
  if (processedDownloadIds.has(downloadItem.id)) {
    return;
  }

  chrome.storage.local.get(["protectionActive", "downloadsScanned", "threatsBlocked", "incidents"], (data) => {
    if (!data.protectionActive) return;

    let totalScanned = (data.downloadsScanned || 0) + 1;
    const filename = (downloadItem.filename || "").toLowerCase();
    const url = (downloadItem.url || "").toLowerCase();

    // Check if filename ends with high-risk executable extension
    const isDangerousExt = DANGEROUS_EXTENSIONS.some(ext => filename.endsWith(ext));
    const isPhishingSource = PHISHING_KEYWORDS.some(kw => url.includes(kw));

    if (isDangerousExt || isPhishingSource) {
      processedDownloadIds.add(downloadItem.id);

      // PAUSE THE DOWNLOAD IMMEDIATELY (Zero Entry - Do not allow writing to disk)
      chrome.downloads.pause(downloadItem.id, () => {
        let totalBlocked = (data.threatsBlocked || 0) + 1;
        const cleanName = downloadItem.filename ? downloadItem.filename.split(/[\\/]/).pop() : "Executable_Payload.exe";
        const reasonText = isDangerousExt 
          ? "Executable Payload" 
          : "Untrusted Phishing Domain";
        
        const incident = {
          time: new Date().toLocaleTimeString(),
          file: cleanName,
          url: downloadItem.url,
          reason: reasonText,
          action: "PAUSED_IN_AIRLOCK_SANDBOX"
        };

        const incidentList = [incident, ...(data.incidents || [])].slice(0, 20);

        chrome.storage.local.set({
          downloadsScanned: totalScanned,
          threatsBlocked: totalBlocked,
          incidents: incidentList,
          lastAlert: incident,
          lastPausedDownloadId: downloadItem.id
        });

        // Trigger rate-limited notification
        showWindowsSecurityAlert(cleanName, reasonText);

        console.warn("🚨 [COGNIGUARD ALERT] Intercepted Threat:", incident);
      });
    } else {
      chrome.storage.local.set({ downloadsScanned: totalScanned });
    }
  });
});

// Listener to resume download if user trusts it
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "RESUME_DOWNLOAD" && request.downloadId) {
    chrome.downloads.resume(request.downloadId, () => {
      chrome.notifications.clear("cogniguard_alert");
      sendResponse({ status: "RESUMED" });
    });
    return true; // Keep message channel open for async response
  }
});
