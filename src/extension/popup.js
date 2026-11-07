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
