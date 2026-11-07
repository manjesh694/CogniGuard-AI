// CogniGuard AI - Popup Script

document.addEventListener("DOMContentLoaded", () => {
  const scannedEl = document.getElementById("scanned-count");
  const blockedEl = document.getElementById("blocked-count");
  const threatBox = document.getElementById("threat-box");
  const threatDesc = document.getElementById("threat-desc");
  const btnTest = document.getElementById("btn-test");
  const statusPill = document.getElementById("status-pill");

  // Load live counts from chrome.storage
  chrome.storage.local.get(["downloadsScanned", "threatsBlocked", "lastAlert"], (data) => {
    if (data.downloadsScanned !== undefined) scannedEl.innerText = data.downloadsScanned;
    if (data.threatsBlocked !== undefined) blockedEl.innerText = data.threatsBlocked;

    if (data.lastAlert) {
      threatBox.style.display = "block";
      threatDesc.innerText = `${data.lastAlert.file} (${data.lastAlert.reason})`;
    }
  });

  // Interactive Test Threat Simulation
  btnTest.addEventListener("click", () => {
    let currentBlocked = parseInt(blockedEl.innerText || "0") + 1;
    let currentScanned = parseInt(scannedEl.innerText || "0") + 1;

    blockedEl.innerText = currentBlocked;
    scannedEl.innerText = currentScanned;

    threatBox.style.display = "block";
    threatDesc.innerText = "Lazarus_Infostealer.pdf.exe paused in cloud airlock. 0 bytes leaked.";

    statusPill.style.background = "rgba(239, 68, 68, 0.2)";
    statusPill.style.color = "#ef4444";
    statusPill.innerHTML = "<span>THREAT CONTAINED</span>";

    setTimeout(() => {
      statusPill.style.background = "rgba(16, 185, 129, 0.15)";
      statusPill.style.color = "#10b981";
      statusPill.innerHTML = '<div class="pulse"></div><span>STATUS: OK</span>';
    }, 2500);

    // Trigger Real Windows Notification via Chrome API
    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23ef4444'><path d='M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm0 15c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1zm1-4h-2V7h2v6z'/></svg>",
      title: "🚨 CogniGuard AI: Threat Intercepted!",
      message: "Lazarus_Infostealer.pdf.exe was contained in Cloud Airlock.\n0 Bytes Leaked → SYSTEM STATUS: OK",
      priority: 2
    });

    // Save to storage
    chrome.storage.local.set({
      downloadsScanned: currentScanned,
      threatsBlocked: currentBlocked,
      lastAlert: {
        file: "Lazarus_Infostealer.pdf.exe",
        reason: "Simulated Infostealer Attack"
      }
    });
  });
});
