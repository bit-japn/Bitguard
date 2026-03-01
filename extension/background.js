// background.js — BitGuard Service Worker

const API_BASE = "http://127.0.0.1:8048";
const VAULT_ORIGIN = "http://localhost:3000"; // vault website origin

// ─────────────────────────────────────────────────────────────────────────────
// SHA1 — HaveIBeenPwned
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM Key Management
// ─────────────────────────────────────────────────────────────────────────────

async function getOrCreateEncryptionKey() {
  const stored = await chrome.storage.local.get("encKeyRaw");

  if (stored.encKeyRaw) {
    const rawKey = new Uint8Array(stored.encKeyRaw);
    return crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // Obtener 32 bytes aleatorios cuánticos desde CESGA QRNG
  const rawKey = await fetchQuantumRandomBytes(32);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,           // no exportable una vez importada
    ["encrypt", "decrypt"]
  );

  await chrome.storage.local.set({
    encKeyRaw: Array.from(rawKey)
  });

  return cryptoKey;
}

async function fetchQuantumRandomBytes(nBytes) {
  // Ajusta el endpoint según la doc de http://qrng.cesga.es:8000/docs
  const response = await fetch(
    `http://qrng.cesga.es:8000/api/get_random_bytes?size=${nBytes}`,
    { method: "GET" }
  );

  if (!response.ok) {
    throw new Error(`QRNG error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();

  // Adaptar según el formato real de la respuesta.
  // Posibilidades habituales:
  //   { bytes: [12, 45, ...] }  → new Uint8Array(data.bytes)
  //   { hex: "0aff..." }        → hexToUint8Array(data.hex)
  //   { data: [...] }           → new Uint8Array(data.data)

  if (Array.isArray(data.bytes)) {
    return new Uint8Array(data.bytes);
  } else if (typeof data.hex === "string") {
    return hexToUint8Array(data.hex);
  } else if (Array.isArray(data.data)) {
    return new Uint8Array(data.data);
  }

  throw new Error("Formato de respuesta QRNG desconocido: " + JSON.stringify(data));
}

function hexToUint8Array(hex) {
  if (hex.length % 2 !== 0) throw new Error("Hex string con longitud impar");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption
// ─────────────────────────────────────────────────────────────────────────────

async function encryptField(plaintext, cryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    encoded
  );

  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);

  return btoa(String.fromCharCode(...combined));
}

// ─────────────────────────────────────────────────────────────────────────────
// Decryption (ANALOGUE TO ENCRYPT)
// Input: base64( IV + ciphertext + tag )
// Output: plaintext string
// ─────────────────────────────────────────────────────────────────────────────

async function decryptField(base64Data, cryptoKey) {
  const combined = Uint8Array.from(atob(base64Data), c =>
    c.charCodeAt(0)
  );

  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault Save
// ─────────────────────────────────────────────────────────────────────────────

async function saveToVault(creds) {
  const cryptoKey = await getOrCreateEncryptionKey();

  const encryptedUser = await encryptField(creds.user ?? "", cryptoKey);
  const encryptedPassword = await encryptField(creds.password ?? "", cryptoKey);

  const vaultId = await getOrCreateVaultId();
  const entryId = crypto.randomUUID();

  const body = {
    vault_id: vaultId,
    entry_id: entryId,
    url: creds.url,
    usr: encryptedUser,
    pwd: encryptedPassword
  };

  const res = await fetch(`${API_BASE}/vault/entries`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
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

// ─────────────────────────────────────────────────────────────────────────────
// PostMessage Bridge — Send AES key to vault website
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  console.log("BitGuard installed.");
});

chrome.runtime.onMessageExternal?.addListener(() => { });

// Listen to tab updates and inject key bridge
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || tab.url.startsWith("chrome://")) return;

  try {
    const cryptoKey = await getOrCreateEncryptionKey();
    const rawKey = await crypto.subtle.exportKey("raw", cryptoKey);

    const base64Key = btoa(
      String.fromCharCode(...new Uint8Array(rawKey))
    );

    // Send to content script (if you have one)
    chrome.tabs.sendMessage(tabId, {
      type: "GLOBAL_AES_KEY",
      keyBase64: base64Key
    }).catch(() => { });

  } catch (e) {
    console.error("Failed to send AES key:", e);
  }
});

// Also respond if vault explicitly requests it
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === "REQUEST_AES_KEY_FROM_VAULT") {
    (async () => {
      const cryptoKey = await getOrCreateEncryptionKey();
      const rawKey = await crypto.subtle.exportKey("raw", cryptoKey);

      const base64Key = btoa(
        String.fromCharCode(...new Uint8Array(rawKey))
      );

      sendResponse({ success: true, keyBase64: base64Key });
    })();

    return true;
  }

  if (message.type === "DECRYPT_ENTRY") {
    (async () => {
      try {
        const cryptoKey = await getOrCreateEncryptionKey();

        const usr = await decryptField(message.payload.usr, cryptoKey);
        const pwd = await decryptField(message.payload.pwd, cryptoKey);

        sendResponse({ success: true, usr, pwd });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
    })();

    return true;
  }

});

console.log("Sending AES key to tab:", tabId, base64Key);
