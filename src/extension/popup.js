// CogniGuard AI - Popup Script with AI Voice, Audio Alert & Allow/Resume

document.addEventListener("DOMContentLoaded", () => {
  const scannedEl = document.getElementById("scanned-count");
  const blockedEl = document.getElementById("blocked-count");
  const threatBox = document.getElementById("threat-box");
  const threatDesc = document.getElementById("threat-desc");
  const btnTest = document.getElementById("btn-test");
  const btnResume = document.getElementById("btn-resume");
  const statusPill = document.getElementById("status-pill");

  let activeDownloadId = null;

  // Load live counts from chrome.storage
  chrome.storage.local.get(["downloadsScanned", "threatsBlocked", "lastAlert", "lastPausedDownloadId"], (data) => {
    if (data.downloadsScanned !== undefined) scannedEl.innerText = data.downloadsScanned;
    if (data.threatsBlocked !== undefined) blockedEl.innerText = data.threatsBlocked;

    if (data.lastAlert) {
      threatBox.style.display = "block";
      threatDesc.innerText = `${data.lastAlert.file} (${data.lastAlert.reason})`;
    }

    if (data.lastPausedDownloadId) {
      activeDownloadId = data.lastPausedDownloadId;
      btnResume.style.display = "block";
    }
  });

  // Handle "Allow & Resume Download" click
  btnResume.addEventListener("click", () => {
    if (activeDownloadId) {
      chrome.runtime.sendMessage({ action: "RESUME_DOWNLOAD", downloadId: activeDownloadId }, (response) => {
        btnResume.style.display = "none";
        threatBox.style.display = "none";
        statusPill.innerHTML = '<div class="pulse"></div><span>STATUS: OK</span>';
        chrome.storage.local.set({ lastPausedDownloadId: null });
      });
    }
  });

  // 1. High-Tech Cyber Defense Chime (Web Audio API)
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
      console.warn("AudioContext init error:", e);
    }
  }

  // 2. Autonomous AI Voice Alert (Web Speech Synthesis)
  function speakAIVoiceAlert(filename) {
    if (!("speechSynthesis" in window)) return;

    window.speechSynthesis.cancel();

    const voiceText = `Warning. Threat detected. The file ${filename} contains a malicious hacked payload. The download has been quarantined in the cloud airlock. Zero bytes leaked. Your system is secure.`;
    
    const utterance = new SpeechSynthesisUtterance(voiceText);
    utterance.rate = 1.05;
    utterance.pitch = 0.95;
    utterance.volume = 1.0;

    const voices = window.speechSynthesis.getVoices();
    const naturalVoice = voices.find(v => v.lang.includes("en") && (v.name.includes("Natural") || v.name.includes("Google") || v.name.includes("David") || v.name.includes("Zira")));
    if (naturalVoice) utterance.voice = naturalVoice;

    window.speechSynthesis.speak(utterance);
  }

  // Interactive Test Threat Simulation with AI Voice & Chime
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

    playCyberChime();

    setTimeout(() => {
      speakAIVoiceAlert("Lazarus Infostealer");
    }, 150);

    setTimeout(() => {
      statusPill.style.background = "rgba(16, 185, 129, 0.15)";
      statusPill.style.color = "#10b981";
      statusPill.innerHTML = '<div class="pulse"></div><span>STATUS: OK</span>';
    }, 2800);

    chrome.notifications.clear("cogniguard_alert", () => {
      chrome.notifications.create("cogniguard_alert", {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "🛡️ CogniGuard AI: Threat Intercepted!",
        message: "Lazarus_Infostealer.pdf.exe was contained in Cloud Airlock.\n0 Bytes Leaked → SYSTEM STATUS: OK",
        priority: 1
      });
    });

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
