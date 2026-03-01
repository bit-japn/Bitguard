// popup.js — BitGuard

const screens = {
  idle: document.getElementById("screen-idle"),
  detected: document.getElementById("screen-detected"),
  success: document.getElementById("screen-success"),
};

function showScreen(name) {
  Object.values(screens).forEach(s => s.classList.remove("active"));
  screens[name].classList.add("active");
}

const dispUrl  = document.getElementById("disp-url");
const dispUser = document.getElementById("disp-user");
const dispPass = document.getElementById("disp-pass");
const pwnedWarn  = document.getElementById("pwned-warning");
const pwnedCount = document.getElementById("pwned-count");
const saveBtn    = document.getElementById("saveBtn");
const dismissBtn = document.getElementById("dismissBtn");
const errorMsg   = document.getElementById("error-msg");

let currentCreds = null;

// ── On open: check for pending credentials ──────────────────────────────────
chrome.storage.local.get(["pendingCreds"], async ({ pendingCreds }) => {
  if (!pendingCreds) {
    showScreen("idle");
    return;
  }

  currentCreds = pendingCreds;
  showScreen("detected");

  // Display fields
  dispUrl.textContent  = truncateUrl(pendingCreds.url);
  dispUser.textContent = pendingCreds.user || "Unknown";
  dispPass.textContent = maskPassword(pendingCreds.password);

  // Check pwned in background
  const result = await chrome.runtime.sendMessage({
    type: "CHECK_PWNED_ONLY",
    payload: { password: pendingCreds.password }
  });

  if (result && result.pwned) {
    pwnedCount.textContent = result.count.toLocaleString();
    pwnedWarn.style.display = "block";
  }
});

// ── Save ─────────────────────────────────────────────────────────────────────
saveBtn.addEventListener("click", async () => {
  saveBtn.disabled = true;
  dismissBtn.disabled = true;
  saveBtn.innerHTML = '<span class="spinner"></span>Saving…';
  errorMsg.style.display = "none";

  try {
    const response = await chrome.runtime.sendMessage({
      type: "CHECK_AND_SAVE",
      payload: currentCreds
    });

    if (response && response.success) {
      showScreen("success");
      setTimeout(() => window.close(), 2000);
    } else {
      throw new Error(response?.error || "Unknown error");
    }
  } catch (e) {
    saveBtn.innerHTML = "Save to vault";
    saveBtn.disabled = false;
    dismissBtn.disabled = false;
    errorMsg.textContent = "Error: " + e.message;
    errorMsg.style.display = "block";
  }
});

// ── Dismiss ───────────────────────────────────────────────────────────────────
dismissBtn.addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "DISMISS" });
  window.close();
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function truncateUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname !== "/" ? u.pathname : "");
  } catch { return url; }
}

function maskPassword(pw) {
  if (!pw) return "••••••••";
  return pw.slice(0, 2) + "•".repeat(Math.max(pw.length - 2, 4));
}

// ── Generate password button (only in idle screen) ────────────────────────────
const generateBtn = document.getElementById("generatePassBtn");
const generatedPassDisplay = document.getElementById("generated-pass");
const copyBtn = document.getElementById("copyPassBtn");

function generatePassword(length = 16) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?";
  let pw = "";
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  array.forEach(v => {
    pw += chars[v % chars.length];
  });
  return pw;
}

// Generar contraseña
generateBtn.addEventListener("click", () => {
  const pw = generatePassword();
  generatedPassDisplay.textContent = pw;
  // also send to the active tab so page can fill its password input
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab && tab.id != null) {
      chrome.tabs.sendMessage(tab.id, { action: "fillPassword", password: pw });
    }
  });
});

// Copiar contraseña al portapapeles
// Copiar contraseña al portapapeles al hacer click en el propio texto
generatedPassDisplay.addEventListener("click", async () => {
  const pw = generatedPassDisplay.textContent;
  if (!pw) return;
  try {
    await navigator.clipboard.writeText(pw);
    const originalText = generatedPassDisplay.textContent;
    generatedPassDisplay.textContent = "Copied!";
    setTimeout(() => generatedPassDisplay.textContent = pw, 1500);
  } catch (e) {
    generatedPassDisplay.textContent = "Error";
    setTimeout(() => generatedPassDisplay.textContent = pw, 1500);
  }
});

async function findURL() {

  const API_URL = "http://127.0.0.1:8048/";

  console.log("hello ")

  try {
    const res = await fetch(API_URL);
    const raw = await res.json();

    credentials = Array.isArray(raw)
      ? raw
      : raw.data
        ? raw.data
        : [];

    if (!credentials.length) {
      tableBody.innerHTML = `<tr><td colspan="4">No credentials found.</td></tr>`;
      return;
    }

    // Wait for AES key before decrypting
    const cryptoKey = await getEncryptionKey();

    // Decrypt usernames immediately
    for (const cred of credentials) {
      try {
        cred.usr = await decryptField(cred.usr, cryptoKey);
      } catch (e) {
        console.error("Username decrypt failed:", e);
        cred.usr = "[decrypt error]";
      }
    }

    renderTable(credentials);

  } catch (err) {
    console.error("Fetch error:", err);
    tableBody.innerHTML = `<tr><td colspan="4">Connection error.</td></tr>`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  findURL();
});
