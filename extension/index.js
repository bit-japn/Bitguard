const API_URL = "http://127.0.0.1:8048/vault/entries";

const tableBody = document.getElementById("tableBody");
const searchInput = document.getElementById("searchInput");

let credentials = [];

let cryptoKey = null;

let resolveKeyReady;
const keyReady = new Promise(resolve => { resolveKeyReady = resolve; });

window.addEventListener("message", (event) => {
        console.log("AES Key:", event.data.encKeyRaw);
});

window.addEventListener("message", async (event) => {
    if (event.data?.type === "VAULT_AES_KEY") {
        const rawKeyBytes = Uint8Array.from(atob(event.data.keyBase64), c => c.charCodeAt(0));
        cryptoKey = await crypto.subtle.importKey(
            "raw", rawKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
        );
        console.log("Vault got the crypto key!");
        resolveKeyReady();
        renderTable(credentials);
    }

    console.log(cryptoKey);
});

window.postMessage({ type: "REQUEST_AES_KEY" }, "*");

async function getEncryptionKey() {
    if (cryptoKey instanceof CryptoKey) return cryptoKey; // ← type-safe check
    await keyReady;
    return cryptoKey;
}

(async () => {
    const cryptoKey = await getEncryptionKey();
    console.log("CryptoKey:", cryptoKey);

    credentials.forEach(async (cred) => {
        try {
            const decrypted = await decryptField(cred.pwd, cryptoKey);
            console.log("Decrypted pwd:", decrypted);
        } catch (e) {
            console.log("Decrypt error:", e);
        }
    });
})();

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

// Fetch
async function fetchCredentials() {
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

function eyeOpenSVG() {
    return `
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
    </svg>`;
}

function eyeClosedSVG() {
    return `
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M17.94 17.94A10.94 10.94 0 0112 20C5 20 1 12 1 12a21.77 21.77 0 015.06-6.94"/>
        <path d="M22.54 11.88A21.85 21.85 0 0023 12s-4 8-11 8a10.94 10.94 0 01-4.94-1.06"/>
        <line x1="1" y1="1" x2="23" y2="23"/>
    </svg>`;
}

// Render
function renderTable(data) {
    tableBody.innerHTML = "";

    data.forEach(cred => {

        const url = cred.url || cred.website || "";
        const usr = cred.usr || cred.username || "";
        const pwd = cred.pwd || cred.password || "";
        const created = cred.created_at || cred.createdAt || "";
        const updated = cred.updated_at || cred.updatedAt || "";

        const row = document.createElement("tr");

        const favicon = `https://www.google.com/s2/favicons?domain=${url}`;
        const hostname = safeHostname(url);

        row.innerHTML = `
            <td>
                <div class="website-cell">
                    <img src="${favicon}">
                    <span>${hostname}</span>
                </div>
            </td>
            <td>${usr}</td>
            <td>
                <div class="password-cell">
                    <span class="password-text">••••••••</span>
                    <button class="eye-btn">👁</button>
                </div>
            </td>
            <td>
                <div class="tooltip">
                    ${timeAgo(updated)}
                    <div class="tooltip-text">
                        Fecha de creación: ${timeAgo(created)}<br>
                        Fecha de modificación: ${timeAgo(updated)}
                    </div>
                </div>
            </td>
        `;

        const eyeBtn = row.querySelector(".eye-btn");
        const passwordText = row.querySelector(".password-text");

        let decryptedCache = null;
        let visible = false;

        eyeBtn.addEventListener("click", async () => {

            if (!decryptedCache) {
              const cryptoKey = await getEncryptionKey();
              if (!cryptoKey) {
                passwordText.textContent = "No key";
                return;
              }
          
              try {
                // Decrypt directly from cred.pwd column
                decryptedCache = await decryptField(cred.pwd, cryptoKey);
              } catch (e) {
                passwordText.textContent = "Decrypt error";
                return;
              }
            }
          
            visible = !visible;
          
            passwordText.textContent = visible
                ? decryptedCache       // show plaintext when revealed
                : "••••••••";          // hide when toggled off
          
            eyeBtn.innerHTML = visible ? eyeClosedSVG() : eyeOpenSVG();
          });

        tableBody.appendChild(row);
    });
}

// Passwords

// todo

// Search
searchInput.addEventListener("input", () => {
    const q = searchInput.value.toLowerCase();

    const filtered = credentials.filter(c =>
        (c.url || "").toLowerCase().includes(q) ||
        (c.usr || c.username || "").toLowerCase().includes(q)
    );

    renderTable(filtered);
});

// Helpers

function formatFullDate(dateStr) {
    if (!dateStr) return "-";
    const d = new Date(dateStr);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString();
}

function timeAgo(dateStr) {
    if (!dateStr) return "-";

    const now = new Date();
    const past = new Date(dateStr);
    const seconds = Math.floor((now - past) / 1000);

    if (seconds < 60) return "just now";

    const intervals = [
        { label: "year", seconds: 31536000 },
        { label: "month", seconds: 2592000 },
        { label: "day", seconds: 86400 },
        { label: "hour", seconds: 3600 },
        { label: "minute", seconds: 60 }
    ];

    for (const interval of intervals) {
        const count = Math.floor(seconds / interval.seconds);
        if (count >= 1) {
            return count === 1
                ? `1 ${interval.label} ago`
                : `${count} ${interval.label}s ago`;
        }
    }

    return "just now";
}

function safeHostname(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

setInterval(() => {
    renderTable(credentials);
}, 60000);

document.addEventListener("DOMContentLoaded", () => {
    fetchCredentials();
});