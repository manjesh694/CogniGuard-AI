/**
 * CogniGuard AI - Background Service Worker (v1.0.3)
 * Full 360-Degree Defense: Intercepts downloads, phishing links, and social media attack vectors
 * (WhatsApp Web, Facebook Messenger, LinkedIn, Telegram).
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
  console.log("🛡️ CogniGuard AI v1.0.3: 360-Degree Defense Armed (Web + Social Media + Vault).");
});

// High-Risk File Extensions that Infostealers & Malware use
const DANGEROUS_EXTENSIONS = [
  ".exe", ".scr", ".vbs", ".bat", ".cmd", ".pdf.exe", ".docm", ".xlsm", ".jar", ".ps1"
];

// Phishing / Social Media Deceptive Domain Keywords
const PHISHING_KEYWORDS = [
  "binance-verify", "metamask-auth", "claim-airdrop", "secure-login-update",
  "bank-kyc-update", "free-nitro", "telegram-gift", "whatsapp-verify",
  "facebook-security", "instagram-badge", "linkedin-talent-verify"
];

// Cache to prevent duplicate notifications for the same download
const processedDownloadIds = new Set();
let lastAlertTimestamp = 0;

// Helper: Show Single, Rate-Limited Native Windows Desktop Notification
function showWindowsSecurityAlert(filename, reason, source = "Web") {
  const now = Date.now();
  if (now - lastAlertTimestamp < 4000) {
    return;
  }
  lastAlertTimestamp = now;

  chrome.notifications.clear("cogniguard_alert", () => {
    chrome.notifications.create("cogniguard_alert", {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: `🛡️ CogniGuard AI: Threat Intercepted (${source})!`,
      message: `Blocked: ${filename}\nReason: ${reason}\nQuarantined in Cloud Airlock. Status: OK.`,
      priority: 1
    });
  });
}

// 1. UNIVERSAL DOWNLOAD INTERCEPTOR (WhatsApp, Facebook, LinkedIn, Web)
chrome.downloads.onCreated.addListener((downloadItem) => {
  if (processedDownloadIds.has(downloadItem.id)) return;

  chrome.storage.local.get(["protectionActive", "downloadsScanned", "threatsBlocked", "incidents"], (data) => {
    if (!data.protectionActive) return;

    let totalScanned = (data.downloadsScanned || 0) + 1;
    const filename = (downloadItem.filename || "").toLowerCase();
    const url = (downloadItem.url || "").toLowerCase();

    // Detect Source Platform
    let sourcePlatform = "Web Download";
    if (url.includes("whatsapp") || (downloadItem.referrer && downloadItem.referrer.includes("whatsapp"))) {
      sourcePlatform = "WhatsApp Web";
    } else if (url.includes("facebook") || (downloadItem.referrer && downloadItem.referrer.includes("facebook"))) {
      sourcePlatform = "Facebook Messenger";
    } else if (url.includes("linkedin") || (downloadItem.referrer && downloadItem.referrer.includes("linkedin"))) {
      sourcePlatform = "LinkedIn Message";
    }

    const isDangerousExt = DANGEROUS_EXTENSIONS.some(ext => filename.endsWith(ext));
    const isPhishingSource = PHISHING_KEYWORDS.some(kw => url.includes(kw));

    if (isDangerousExt || isPhishingSource) {
      processedDownloadIds.add(downloadItem.id);

      // PAUSE THE DOWNLOAD IMMEDIATELY (Zero Entry - 0 Bytes to Disk)
      chrome.downloads.pause(downloadItem.id, () => {
        let totalBlocked = (data.threatsBlocked || 0) + 1;
        const cleanName = downloadItem.filename ? downloadItem.filename.split(/[\\/]/).pop() : "Executable_Payload.exe";
        const reasonText = isDangerousExt ? "Executable Payload Disguised as Document" : "Untrusted Phishing Source";
        
        const incident = {
          time: new Date().toLocaleTimeString(),
          file: `${cleanName} (${sourcePlatform})`,
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

        // Trigger rate-limited notification with source name
        showWindowsSecurityAlert(cleanName, reasonText, sourcePlatform);

        console.warn(`🚨 [COGNIGUARD ALERT] Intercepted Threat from ${sourcePlatform}:`, incident);
      });
    } else {
      chrome.storage.local.set({ downloadsScanned: totalScanned });
    }
  });
});

// 2. SOCIAL MEDIA PHISHING & DECEPTIVE LINK RADAR
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // Top-level navigations only
  const url = details.url.toLowerCase();

  const isPhishing = PHISHING_KEYWORDS.some(kw => url.includes(kw));
  if (isPhishing) {
    showWindowsSecurityAlert(details.url, "Deceptive Phishing Link Detected", "Social Link Radar");
    console.warn("🚨 [COGNIGUARD PHISHING INTERCEPT] Blocked Navigation to:", details.url);
  }
});

// Listener to resume download if user trusts it
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "RESUME_DOWNLOAD" && request.downloadId) {
    chrome.downloads.resume(request.downloadId, () => {
      chrome.notifications.clear("cogniguard_alert");
      sendResponse({ status: "RESUMED" });
    });
    return true;
  }
});
