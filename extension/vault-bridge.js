window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    if (event.data?.type !== "REQUEST_VAULT_KEY") return;

    const response = await chrome.runtime.sendMessage({ type: "REQUEST_VAULT_KEY" });

    if (response?.keyBase64) {
        window.postMessage({ type: "VAULT_AES_KEY", keyBase64: response.keyBase64 }, "*");
    }
});