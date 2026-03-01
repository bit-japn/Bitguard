// background.js — BitGuard (Arquitectura unificada V1 + Detección V2)

const API_BASE = "http://127.0.0.1:8048";
const VAULT_ORIGIN = "http://localhost:3000";

// ─────────────────────────────────────────────────────────────────────────────
// 1. Criptografía y Seguridad (Core V1)
// ─────────────────────────────────────────────────────────────────────────────

// The encryption key is stored in chrome.storage.local as a raw byte array.
// On first run we generate a new AES‑GCM key and persist it; afterwards we
// import the same bytes so the key is stable across browser restarts.
async function getOrCreateEncryptionKey() {
    const stored = await chrome.storage.local.get("encKeyRaw");

    if (stored.encKeyRaw) {
        const rawKey = new Uint8Array(stored.encKeyRaw);
        return crypto.subtle.importKey(
            "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
        );
    }

    // first launch – generate+persist
    const cryptoKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const rawKey = await crypto.subtle.exportKey("raw", cryptoKey);
    await chrome.storage.local.set({ encKeyRaw: Array.from(new Uint8Array(rawKey)) });
    return cryptoKey;
}

// decrypts a single field previously encrypted with `encryptField` below
async function decryptField(encryptedPayload, cryptoKey) {
    const combined = Uint8Array.from(atob(encryptedPayload), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

// mirror of vault page's decryptField; needed when background saves entries
async function encryptField(plaintext, cryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encoded);

    const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.byteLength);
    return btoa(String.fromCharCode(...combined));
}

// helper used when the extension saves a new login; encrypts fields and POSTs to the
// backend API exactly the same way the original app expects.
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
// 2. Utilidades HIBP (Consolidada)
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
    const hash = await sha1(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) return { pwned: false, count: 0 };
    const lines = (await res.text()).split("\n");
    const match = lines.find(l => l.startsWith(suffix));
    return match ? { pwned: true, count: parseInt(match.split(":")[1], 10) } : { pwned: false, count: 0 };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Centralizador de Mensajes (Merge de V1 y V2)
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    // A. FLUJO DE LOGIN (V2)
    if (message.type === "LOGIN_DETECTED") {
        chrome.storage.local.set({ pendingCreds: message.payload });
        chrome.action.setBadgeText({ text: "!" });
        chrome.action.setBadgeBackgroundColor({ color: "#e74c3c" });
        // open popup so user is immediately shown detected credentials
        chrome.action.openPopup();
        return;
    }

    // B. FLUJO DE GUARDADO (V2)
    if (message.type === "CHECK_AND_SAVE") {
        (async () => {
            const pwnedResult = await checkPwned(message.payload.password);
            try {
                await saveToVault(message.payload);
            } catch (err) {
                console.error("Failed to save entry:", err);
                sendResponse({ success: false, error: err.message, pwned: pwnedResult });
                return;
            }
            chrome.storage.local.remove("pendingCreds");
            chrome.action.setBadgeText({ text: "" });
            sendResponse({ success: true, pwned: pwnedResult });
        })();
        return true; 
    }

    // helper used by popup before saving, just perform HIBP without clearing state
    if (message.type === "CHECK_PWNED_ONLY") {
        (async () => {
            const pwnedResult = await checkPwned(message.payload.password);
            sendResponse(pwnedResult);
        })();
        return true;
    }

    // dismiss button in popup clicked
    if (message.type === "DISMISS") {
        chrome.storage.local.remove("pendingCreds");
        chrome.action.setBadgeText({ text: "" });
        return; // synchronous
    }

    // C. FLUJO DE SEGURIDAD/LLAVE (V1 - Protegido)
    if (message.type === "REQUEST_AES_KEY_FROM_VAULT") {
        (async () => {
            const cryptoKey = await getOrCreateEncryptionKey();
            const rawKey = await crypto.subtle.exportKey("raw", cryptoKey);
            const base64Key = btoa(String.fromCharCode(...new Uint8Array(rawKey)));
            sendResponse({ success: true, keyBase64: base64Key });
        })();
        return true;
    }

    if (message.type === "DECRYPT_ENTRY") {
        (async () => {
            const cryptoKey = await getOrCreateEncryptionKey();
            const usr = await decryptField(message.payload.user, cryptoKey);
            const pwd = await decryptField(message.payload.password, cryptoKey);
            sendResponse({ success: true, user: usr, password: pwd });
        })();
        return true;
    }
});

chrome.tabs.onUpdated.addListener(() => {

  findURL();
})

async function findURL() {

  const API_URL = "http://127.0.0.1:8048/vault/entries";

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
      console.log("not found");
      return;
    }

    chrome.tabs.query({
        active: true,
        currentWindow: true
    },

    
        (tabs) => {

            const activeTab = tabs[0];
            const activeTabUrl = activeTab.url;

            const realURL = new URL(activeTabUrl);

            const hostname = realURL.hostname.replace(/^www\./, '');

            const hasURL = credentials.find((item) =>
                item.url.replace(/^www\./, '') === hostname
            );

            

            console.log(hasURL);

            if (hasURL) {
                console.log("Match found:", hasURL);

                chrome.scripting.executeScript({
                    target: { tabId: activeTab.id },
                    func: (username, password) => {
                        const userInput =
                            document.querySelector('input[type="email"]') ||
                            document.querySelector('input[type="text"]');

                        const passInput =
                            document.querySelector('input[type="password"]');

                        if (userInput) userInput.value = username;
                        if (passInput) passInput.value = password;
                    },
                    args: [hasURL.usr, hasURL.pwd],
                });
            } else {
                console.log("No matching credentials found.");
            }
        }
    

    )

  } catch (err) {
    console.error("Fetch error:", err);
    tableBody.innerHTML = `<tr><td colspan="4">Connection error.</td></tr>`;
  }
}

