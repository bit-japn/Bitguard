const API_URL = "http://127.0.0.1:8048/vault/entries/10213333";

const tableBody = document.getElementById("tableBody");
const searchInput = document.getElementById("searchInput");

let credentials = [];

// Fetch
async function fetchCredentials() {
    try {
        const res = await fetch(API_URL);
        const raw = await res.json();

        console.log("API RESPONSE:", raw);

        // Support both direct array OR wrapped {data: [...]}
        credentials = Array.isArray(raw) ? raw :
            raw.data ? raw.data :
                [];

        if (!credentials.length) {
            tableBody.innerHTML = `<tr><td colspan="4">No credentials found.</td></tr>`;
            return;
        }

        renderTable(credentials);

    } catch (err) {
        console.error("Fetch error:", err);
        tableBody.innerHTML = `<tr><td colspan="4">Connection error.</td></tr>`;
    }
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
            <td>••••••••</td>
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

        tableBody.appendChild(row);
    });
}

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

fetchCredentials();