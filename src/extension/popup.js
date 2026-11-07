// CogniGuard AI - Popup Script with AI Voice & Cyber Audio Alert

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

  // 1. High-Tech Cyber Defense Chime (Web Audio API)
  function playCyberChime() {
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();

      osc.type = "sine";
      // Dual-tone futuristic radar alert frequency
      osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5
      osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.25); // Drop to A4

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

    window.speechSynthesis.cancel(); // Stop any previous speech

    const voiceText = `Warning. Threat detected. The file ${filename} contains a malicious hacked payload. The download has been quarantined in the cloud airlock. Zero bytes leaked. Your system is secure.`;
    
    const utterance = new SpeechSynthesisUtterance(voiceText);
    utterance.rate = 1.05; // Slightly crisp, professional speed
    utterance.pitch = 0.95; // Confident, authoritative AI voice
    utterance.volume = 1.0;

    // Pick a natural English voice if available
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

    // Play High-Tech Audio Chime first
    playCyberChime();

    // Trigger Autonomous AI Voice Alert
    setTimeout(() => {
      speakAIVoiceAlert("Lazarus Infostealer");
    }, 150);

    setTimeout(() => {
      statusPill.style.background = "rgba(16, 185, 129, 0.15)";
      statusPill.style.color = "#10b981";
      statusPill.innerHTML = '<div class="pulse"></div><span>STATUS: OK</span>';
    }, 2800);

    // Native Windows Desktop Notification
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
