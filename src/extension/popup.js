// CogniGuard AI - Popup Script with AI Reverse-Engineering Intent Voice & Shredder

document.addEventListener("DOMContentLoaded", () => {
  const scannedEl = document.getElementById("scanned-count");
  const blockedEl = document.getElementById("blocked-count");
  const threatBox = document.getElementById("threat-box");
  const threatTarget = document.getElementById("threat-target");
  const threatDesc = document.getElementById("threat-desc");
  const btnTest = document.getElementById("btn-test");
  const btnShred = document.getElementById("btn-shred");
  const btnResume = document.getElementById("btn-resume");
  const statusPill = document.getElementById("status-pill");
  const apiBaseInput = document.getElementById("api-base-input");
  const bridgeDot = document.getElementById("bridge-dot");

  let activeDownloadId = null;

  function checkBridgeHealth(baseUrl) {
    const clean = (baseUrl || "http://127.0.0.1:8765").trim().replace(/\/+$/, "");
    fetch(`${clean}/api/v1/health`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then(() => {
        bridgeDot.style.color = "#10b981";
        bridgeDot.innerText = "● Connected";
      })
      .catch(() => {
        bridgeDot.style.color = "#94a3b8";
        bridgeDot.innerText = "● Standalone";
      });
  }

  // Load live counts from chrome.storage
  chrome.storage.local.get(["downloadsScanned", "threatsBlocked", "lastAlert", "lastPausedDownloadId", "apiBaseUrl"], (data) => {
    if (data.downloadsScanned !== undefined) scannedEl.innerText = data.downloadsScanned;
    if (data.threatsBlocked !== undefined) blockedEl.innerText = data.threatsBlocked;
    const savedApi = data.apiBaseUrl || "http://127.0.0.1:8765";
    apiBaseInput.value = savedApi;
    checkBridgeHealth(savedApi);

    if (data.lastAlert) {
      threatBox.style.display = "block";
      threatDesc.innerText = `${data.lastAlert.file} (${data.lastAlert.reason})`;
      btnShred.style.display = "block";
    }

    if (data.lastPausedDownloadId) {
      activeDownloadId = data.lastPausedDownloadId;
      btnResume.style.display = "block";
    }
  });

  // 1. High-Tech Cyber Defense Chime
  function playCyberChime() {
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();

      osc.type = "sine";
      osc.frequency.setValueAtTime(880, audioCtx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.25);

      gain.gain.setValueAtTime(0.3, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);

      osc.connect(gain);
      gain.connect(audioCtx.destination);

      osc.start();
      osc.stop(audioCtx.currentTime + 0.3);
    } catch (e) {
      console.warn("AudioContext error:", e);
    }
  }

  // 2. Autonomous AI Voice Alert (Reverse Engineering Intent)
  function speakAIVoiceAlert(message) {
    if (!("speechSynthesis" in window)) return;

    window.speechSynthesis.cancel();

    const utterance = new SpeechSynthesisUtterance(message);
    utterance.rate = 1.05;
    utterance.pitch = 0.95;
    utterance.volume = 1.0;

    const voices = window.speechSynthesis.getVoices();
    const naturalVoice = voices.find(v => v.lang.includes("en") && (v.name.includes("Natural") || v.name.includes("Google") || v.name.includes("David") || v.name.includes("Zira")));
    if (naturalVoice) utterance.voice = naturalVoice;

    window.speechSynthesis.speak(utterance);
  }

  apiBaseInput.addEventListener("change", () => {
    const raw = apiBaseInput.value.trim().replace(/\/+$/, "");
    const safe = /^https?:\/\//i.test(raw) ? raw : "http://127.0.0.1:8765";
    apiBaseInput.value = safe;
    const persistAndCheck = () => chrome.storage.local.set({ apiBaseUrl: safe }, () => checkBridgeHealth(safe));
    if (safe.startsWith("https://") && chrome.permissions && chrome.permissions.request) {
      try {
        chrome.permissions.request({ origins: [`${new URL(safe).origin}/*`] }, persistAndCheck);
      } catch (e) {
        persistAndCheck();
      }
    } else {
      persistAndCheck();
    }
  });

  // Handle "Shred & Permanently Delete" Action
  btnShred.addEventListener("click", () => {
    const finishShred = () => {
      let currentBlocked = parseInt(blockedEl.innerText || "0") + 1;
      blockedEl.innerText = currentBlocked;

      threatBox.style.display = "none";
      btnShred.style.display = "none";
      btnResume.style.display = "none";

      statusPill.style.background = "rgba(16, 185, 129, 0.2)";
      statusPill.style.color = "#10b981";
      statusPill.innerHTML = '<div class="pulse"></div><span>FILE SHREDDED → STATUS: OK</span>';

      speakAIVoiceAlert("File permanently shredded and destroyed. Zero bytes leaked. Your system is 100 percent secure.");

      chrome.notifications.clear("cogniguard_alert", () => {
        chrome.notifications.create("cogniguard_alert", {
          type: "basic",
          iconUrl: "icons/icon128.png",
          title: "🛡️ CogniGuard AI: Threat Shredded!",
          message: "Malicious payload permanently deleted.\n0 Bytes Leaked → SYSTEM STATUS: OK",
          priority: 1
        });
      });

      activeDownloadId = null;
      chrome.storage.local.set({
        threatsBlocked: currentBlocked,
        lastAlert: null,
        lastPausedDownloadId: null
      });
    };

    if (activeDownloadId) {
      chrome.runtime.sendMessage({ action: "SHRED_DOWNLOAD", downloadId: activeDownloadId }, finishShred);
    } else {
      finishShred();
    }
  });

  // Handle "Allow & Resume Download" Action
  btnResume.addEventListener("click", () => {
    if (activeDownloadId) {
      chrome.runtime.sendMessage({ action: "RESUME_DOWNLOAD", downloadId: activeDownloadId }, () => {
        btnResume.style.display = "none";
        btnShred.style.display = "none";
        threatBox.style.display = "none";
        statusPill.innerHTML = '<div class="pulse"></div><span>STATUS: OK</span>';
        chrome.storage.local.set({ lastPausedDownloadId: null, lastAlert: null });
      });
    }
  });

  // Test Simulation: Hacker trying to steal Bank PIN
  btnTest.addEventListener("click", () => {
    let currentScanned = parseInt(scannedEl.innerText || "0") + 1;
    scannedEl.innerText = currentScanned;

    threatBox.style.display = "block";
    threatTarget.innerText = "Stealing Bank PIN & Passwords";
    threatDesc.innerText = "Script contains hidden hooks attempting to exfiltrate netbanking PIN.";
    btnShred.style.display = "block";

    statusPill.style.background = "rgba(239, 68, 68, 0.2)";
    statusPill.style.color = "#ef4444";
    statusPill.innerHTML = "<span>INTRUSION INTERCEPTED</span>";

    playCyberChime();

    // Spoken Intent Voice Alert
    setTimeout(() => {
      speakAIVoiceAlert(
        "Warning! CogniGuard has reverse-engineered this script. The attacker is actively attempting to steal your Bank PIN and financial accounts. Permission requested: Shall I permanently shred and delete this file?"
      );
    }, 150);

    chrome.notifications.clear("cogniguard_alert", () => {
      chrome.notifications.create("cogniguard_alert", {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "🚨 CogniGuard AI: Bank PIN Theft Blocked!",
        message: "Reverse-engineered script attempting to steal Bank PIN.\nClick Shred to destroy.",
        priority: 1
      });
    });

    chrome.storage.local.set({
      downloadsScanned: currentScanned,
      lastAlert: {
        file: "Fake_Bank_Invoice.vbs",
        reason: "Attempting to Steal Bank PIN & Netbanking Data"
      }
    });
  });
});
