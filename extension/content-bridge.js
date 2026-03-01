// content-bridge.js
// Bridge between vault website (localhost:3000) and BitGuard extension

// Listen for vault requesting AES key
window.addEventListener("message", async (event) => {

    // Only accept messages from same window
    if (event.source !== window) return;

    if (event.data?.type === "REQUEST_AES_KEY") {

        try {
            const response = await chrome.runtime.sendMessage({
                type: "REQUEST_AES_KEY_FROM_VAULT"
            });

            if (response?.success) {
                window.postMessage({
                    type: "VAULT_AES_KEY",
                    keyBase64: response.keyBase64
                }, "*");
            }

        } catch (err) {
            console.error("Failed to get AES key:", err);
        }
    }
});