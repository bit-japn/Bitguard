// background.js — BitGuard Service Worker

const API_BASE = "http://127.0.0.1:8048";

// ─── HaveIBeenPwned check ─────────────────────────────────────────────────────
async function sha1(str) {
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function checkPwned(password) {
  try {
    const hash = await sha1(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" }
    });
    if (!res.ok) return { pwned: false, count: 0 };
    const lines = (await res.text()).split("\n");
    const match = lines.find(l => l.startsWith(suffix));
    if (match) {
      const count = parseInt(match.split(":")[1], 10);
      return { pwned: true, count };
    }
    return { pwned: false, count: 0 };
  } catch (e) {
    console.error("HIBP check failed:", e);
    return { pwned: false, count: 0, error: true };
  }
}

// ─── Encryption key — stored inside Chromium (chrome.storage.local) ──────────
// First run: generates a random AES-256 key and saves it to chrome.storage.local.
// All subsequent runs: loads the same key from storage.
// The key never leaves Chromium — no server, no .env file.

async function getOrCreateEncryptionKey() {
  const stored = await chrome.storage.local.get("encKeyRaw");

  if (stored.encKeyRaw) {
    const rawKey = new Uint8Array(stored.encKeyRaw);
    return crypto.subtle.importKey(
      "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
  }

  // First run — generate and persist
  const cryptoKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
  const rawKey = await crypto.subtle.exportKey("raw", cryptoKey);
  await chrome.storage.local.set({ encKeyRaw: Array.from(new Uint8Array(rawKey)) });
  return cryptoKey;
}

// ─── Encrypt a single field ───────────────────────────────────────────────────
// Each call uses a fresh random 96-bit IV.
// Output: base64( IV [12 bytes] + ciphertext + GCM tag [16 bytes] )

async function encryptField(plaintext, cryptoKey) {
  const iv         = crypto.getRandomValues(new Uint8Array(12));
  const encoded    = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encoded);

  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

// ─── Save to vault ────────────────────────────────────────────────────────────
// user and password are encrypted individually, then packed into the "data"
// field the backend already expects — keeping the server contract intact.
// url stays top-level and plain so the server can filter/search by site.

async function saveToVault(creds) {
  const cryptoKey = await getOrCreateEncryptionKey();

  const encryptedUser     = await encryptField(creds.user     ?? "", cryptoKey);
  const encryptedPassword = await encryptField(creds.password ?? "", cryptoKey);

  const vaultId = await getOrCreateVaultId();
  const entryId = crypto.randomUUID();

  const body = {
    vault_id: vaultId,
    entry_id: entryId,
    url:      creds.url,  // plain — intentionally not encrypted
    data:     JSON.stringify({
      encrypted_user:     encryptedUser,      // AES-256-GCM, individually encrypted
      encrypted_password: encryptedPassword   // AES-256-GCM, individually encrypted
    })
  };

  const res = await fetch(`${API_BASE}/vault/entries`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(body)
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${detail}`);
  }
  return await res.json();
}

async function getOrCreateVaultId() {
  const stored = await chrome.storage.local.get("vaultId");
  if (stored.vaultId) return stored.vaultId;
  const newId = crypto.randomUUID();
  await chrome.storage.local.set({ vaultId: newId });
  return newId;
}

// ─── Auto-open the popup inside the current Chromium session ──────────────────
// chrome.action.openPopup() is the native way but requires a user gesture in MV3.
// Instead we open popup.html as a chrome "popup" window, which always attaches
// to the existing Chromium session rather than spawning a new browser instance.
// We anchor it near the top-right of the current window (where the toolbar is).

async function openDetectedPopup() {
  // Get the currently focused window so we can position the popup next to it
  const currentWindow = await chrome.windows.getLastFocused({ populate: false });

  const width  = 340;
  const height = 450;

  // Position top-right of the current window, like a real extension popup
  const left = (currentWindow.left ?? 0) + (currentWindow.width  ?? 1200) - width  - 20;
  const top  = (currentWindow.top  ?? 0) + 60; // below the toolbar

  await chrome.windows.create({
    url:     chrome.runtime.getURL("popup.html"),
    type:    "popup",
    width,
    height,
    left:    Math.max(0, Math.round(left)),
    top:     Math.max(0, Math.round(top)),
    focused: true
  });
}

// ─── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "LOGIN_DETECTED") {
    chrome.storage.local.set({ pendingCreds: message.payload }, async () => {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#e74c3c" });
      await openDetectedPopup();
    });
    return;
  }

  if (message.type === "CHECK_AND_SAVE") {
    const creds = message.payload;
    (async () => {
      try {
        const pwnedResult = await checkPwned(creds.password);
        await saveToVault(creds);
        chrome.action.setBadgeText({ text: "" });
        chrome.storage.local.remove("pendingCreds");
        sendResponse({ success: true, pwned: pwnedResult });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();
    return true;
  }

  if (message.type === "CHECK_PWNED_ONLY") {
    (async () => {
      const result = await checkPwned(message.payload.password);
      sendResponse(result);
    })();
    return true;
  }

  if (message.type === "DISMISS") {
    chrome.action.setBadgeText({ text: "" });
    chrome.storage.local.remove("pendingCreds");
    sendResponse({ ok: true });
    return;
  }
});
