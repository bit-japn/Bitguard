// background.js — BitGuard (Arquitectura unificada V1 + Detección V2)

const API_BASE = "http://127.0.0.1:8048";
const VAULT_ORIGIN = "http://localhost:3000";

// ─────────────────────────────────────────────────────────────────────────────
// 1. Criptografía y Seguridad (Core V1)
// ─────────────────────────────────────────────────────────────────────────────

async function getOrCreateEncryptionKey() {
    // Aquí iría tu lógica de recuperar o generar la llave
    // Asumimos que ya tienes una función que obtiene la llave del almacenamiento
    // o la deriva de una contraseña maestra/valor local.
    // ... tu implementación actual de getOrCreateEncryptionKey ...
}

async function decryptField(encryptedPayload, cryptoKey) {
    // ... tu implementación de descifrado V1 ...
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Utilidades HIBP (Consolidada)
// ─────────────────────────────────────────────────────────────────────────────

async function sha1(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("").toUpperCase();
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
            // Aquí llamarías a tu lógica de guardado
            chrome.storage.local.remove("pendingCreds");
            chrome.action.setBadgeText({ text: "" });
            sendResponse({ success: true, pwned: pwnedResult });
        })();
        return true; 
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