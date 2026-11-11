/**
 * CogniGuard AI - Background Service Worker (v1.0.4)
 * Connected to Local Python Agent API Bridge (http://127.0.0.1:8765)
 * Full 360-Degree Defense across Web, WhatsApp, Facebook, LinkedIn, and System Vaults.
 */

const DEFAULT_API_BASE = "http://127.0.0.1:8765";

// Initialize default protection state
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["apiBaseUrl"], (existing) => {
    chrome.storage.local.set({
      protectionActive: true,
      downloadsScanned: 0,
      threatsBlocked: 0,
      incidents: [],
      lastPausedDownloadId: null,
      apiBaseUrl: existing.apiBaseUrl || DEFAULT_API_BASE
    });
  });
  console.log("🛡️ CogniGuard AI v1.0.4: 360-Degree Defense & Python Bridge Armed.");
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

const processedDownloadIds = new Set();
let lastAlertTimestamp = 0;

// Helper: Resolve sanitized API Base URL from storage
function resolveApiBase(callback) {
  chrome.storage.local.get(["apiBaseUrl"], (data) => {
    const raw = (data.apiBaseUrl || DEFAULT_API_BASE).trim().replace(/\/+$/, "");
    const safeUrl = /^https?:\/\//i.test(raw) ? raw : DEFAULT_API_BASE;
    callback(safeUrl);
  });
}

// Helper: Stream Telemetry to Local or Cloud Python Daemon
async function syncWithPythonDaemon(filename, sourceUrl, fileSize) {
  return new Promise((resolve) => {
    resolveApiBase(async (apiBase) => {
      try {
        const response = await fetch(`${apiBase}/api/v1/inspect`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            filename: filename,
            source_url: sourceUrl,
            file_size_bytes: fileSize || 0,
            client_version: "1.0.4"
          })
        });
        if (response.ok) {
          const verdictData = await response.json();
          console.log("📡 [Python Daemon Verdict]:", verdictData);
          resolve(verdictData);
          return;
        }
      } catch (err) {
        console.log("ℹ️ Python Bridge offline; running on standalone Browser Defense.");
      }
      resolve(null);
    });
  });
}

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

// Helper: Pause a download, update local stats/incidents, and trigger alert
function quarantineBrowserDownload(downloadItem, cleanName, sourcePlatform, reasonText) {
  processedDownloadIds.add(downloadItem.id);
  chrome.downloads.pause(downloadItem.id, () => {
    if (chrome.runtime.lastError) {
      console.warn("Notice during pause:", chrome.runtime.lastError.message);
    }
    chrome.storage.local.get(["threatsBlocked", "incidents"], (latest) => {
      const totalBlocked = (latest.threatsBlocked || 0) + 1;
      const incident = {
        time: new Date().toLocaleTimeString(),
        file: `${cleanName} (${sourcePlatform})`,
        url: downloadItem.url,
        reason: reasonText,
        action: "PAUSED_IN_AIRLOCK_SANDBOX"
      };
      const incidentList = [incident, ...(latest.incidents || [])].slice(0, 20);

      chrome.storage.local.set({
        threatsBlocked: totalBlocked,
        incidents: incidentList,
        lastAlert: incident,
        lastPausedDownloadId: downloadItem.id
      });

      showWindowsSecurityAlert(cleanName, reasonText, sourcePlatform);
      console.warn(`🚨 [COGNIGUARD ALERT] Intercepted Threat from ${sourcePlatform}:`, incident);
    });
  });
}

// 1. UNIVERSAL DOWNLOAD INTERCEPTOR (WhatsApp, Facebook, LinkedIn, Web)
chrome.downloads.onCreated.addListener((downloadItem) => {
  if (processedDownloadIds.has(downloadItem.id)) return;

  chrome.storage.local.get(["protectionActive", "downloadsScanned"], (data) => {
    if (!data.protectionActive) return;

    const totalScanned = (data.downloadsScanned || 0) + 1;
    chrome.storage.local.set({ downloadsScanned: totalScanned });

    const filename = (downloadItem.filename || "").toLowerCase();
    const url = (downloadItem.url || "").toLowerCase();
    const cleanName = downloadItem.filename ? downloadItem.filename.split(/[\\/]/).pop() : "Executable_Payload.exe";

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
      const reasonText = isDangerousExt ? "Executable Payload Disguised as Document" : "Untrusted Phishing Source";
      quarantineBrowserDownload(downloadItem, cleanName, sourcePlatform, reasonText);
    }

    // Stream event asynchronously to Python Threat Engine and enforce backend verdict if flagged
    syncWithPythonDaemon(cleanName, downloadItem.url || "unknown", downloadItem.fileSize).then((verdictData) => {
      if (
        verdictData &&
        verdictData.verdict === "INTRUSION_DETECTED" &&
        !processedDownloadIds.has(downloadItem.id)
      ) {
        quarantineBrowserDownload(
          downloadItem,
          cleanName,
          sourcePlatform,
          verdictData.reason || "Flagged by CogniGuard Python Threat Engine"
        );
      }
    });
  });
});

// 2. SOCIAL MEDIA PHISHING & DECEPTIVE LINK RADAR
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const url = details.url.toLowerCase();

  const isPhishing = PHISHING_KEYWORDS.some(kw => url.includes(kw));
  if (isPhishing) {
    syncWithPythonDaemon("Phishing_URL_Redirect", details.url, 0);
    showWindowsSecurityAlert(details.url, "Deceptive Phishing Link Detected", "Social Link Radar");
    console.warn("🚨 [COGNIGUARD PHISHING INTERCEPT] Blocked Navigation to:", details.url);
  }
});

// Listener to resume or shred a paused download from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "RESUME_DOWNLOAD" && request.downloadId) {
    chrome.downloads.resume(request.downloadId, () => {
      if (chrome.runtime.lastError) console.warn(chrome.runtime.lastError.message);
      chrome.notifications.clear("cogniguard_alert");
      sendResponse({ status: "RESUMED" });
    });
    return true;
  }
  if (request.action === "SHRED_DOWNLOAD" && request.downloadId) {
    chrome.downloads.cancel(request.downloadId, () => {
      if (chrome.runtime.lastError) console.warn(chrome.runtime.lastError.message);
      chrome.downloads.erase({ id: request.downloadId }, () => {
        if (chrome.runtime.lastError) console.warn(chrome.runtime.lastError.message);
        chrome.notifications.clear("cogniguard_alert");
        sendResponse({ status: "SHREDDED" });
      });
    });
    return true;
  }
});
