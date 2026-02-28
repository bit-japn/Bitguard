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

// ─── Native notification with Save / Dismiss buttons ─────────────────────────
// Shows a system notification when a login is detected.
// Buttons: [Save to vault] [Dismiss]
// Clicking Save triggers the full encrypt+save flow right here in the background.

const NOTIF_ID = "bitguard-login-detected";

async function showLoginNotification(creds) {
  // Run HIBP check in parallel so we can enrich the notification message
  const pwnedResult = await checkPwned(creds.password);

  let hostname = creds.url;
  try { hostname = new URL(creds.url).hostname; } catch {}

  const message = pwnedResult.pwned
    ? `⚠️ Password found in ${pwnedResult.count.toLocaleString()} breaches!\nUser: ${creds.user || "unknown"}`
    : `User: ${creds.user || "unknown"}`;

  chrome.notifications.create(NOTIF_ID, {
    type:     "basic",
    iconUrl:  chrome.runtime.getURL("icons/icon48.png"),
    title:    `BitGuard — login detected on ${hostname}`,
    message,
    buttons:  [
      { title: "💾 Save to vault" },
      { title: "✕ Dismiss" }
    ],
    requireInteraction: true   // keeps it visible until the user acts
  });
}

// ─── Notification button clicks ───────────────────────────────────────────────
chrome.notifications.onButtonClicked.addListener(async (notifId, btnIndex) => {
  if (notifId !== NOTIF_ID) return;
  chrome.notifications.clear(NOTIF_ID);

  const { pendingCreds } = await chrome.storage.local.get("pendingCreds");
  if (!pendingCreds) return;

  if (btnIndex === 0) {
    // Save to vault
    try {
      await saveToVault(pendingCreds);
      chrome.action.setBadgeText({ text: "" });
      chrome.storage.local.remove("pendingCreds");
      // Brief "saved" confirmation notification
      chrome.notifications.create("bitguard-saved", {
        type:    "basic",
        iconUrl: chrome.runtime.getURL("icons/icon48.png"),
        title:   "BitGuard — saved ✅",
        message: "Credentials stored in your vault."
      });
    } catch (e) {
      chrome.notifications.create("bitguard-error", {
        type:    "basic",
        iconUrl: chrome.runtime.getURL("icons/icon48.png"),
        title:   "BitGuard — save failed ❌",
        message: e.message
      });
    }
  } else {
    // Dismiss
    chrome.action.setBadgeText({ text: "" });
    chrome.storage.local.remove("pendingCreds");
  }
});

// Also handle clicking the notification body itself (same as Save)
chrome.notifications.onClicked.addListener(async (notifId) => {
  if (notifId !== NOTIF_ID) return;
  chrome.notifications.clear(NOTIF_ID);
  const { pendingCreds } = await chrome.storage.local.get("pendingCreds");
  if (!pendingCreds) return;
  try {
    await saveToVault(pendingCreds);
    chrome.action.setBadgeText({ text: "" });
    chrome.storage.local.remove("pendingCreds");
    chrome.notifications.create("bitguard-saved", {
      type:    "basic",
      iconUrl: chrome.runtime.getURL("icons/icon48.png"),
      title:   "BitGuard — saved ✅",
      message: "Credentials stored in your vault."
    });
  } catch (e) {
    chrome.notifications.create("bitguard-error", {
      type:    "basic",
      iconUrl: chrome.runtime.getURL("icons/icon48.png"),
      title:   "BitGuard — save failed ❌",
      message: e.message
    });
  }
});

// ─── Message handler ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "LOGIN_DETECTED") {
    chrome.storage.local.set({ pendingCreds: message.payload }, async () => {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#e74c3c" });
      await showLoginNotification(message.payload);
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
