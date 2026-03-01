// content.js — BitGuard
// Listens for form submissions and detects login credentials

(function () {
  // Avoid injecting twice
  if (window.__bitguardInjected) return;
  window.__bitguardInjected = true;

  function findLoginForm(form) {
    const inputs = Array.from(form.querySelectorAll("input"));
    const passwordInput = inputs.find(i => i.type === "password");
    if (!passwordInput) return null;

    const userInput = inputs.find(i =>
      i.type === "email" ||
      (i.type === "text" && /user|email|login|name/i.test(i.name + i.id + i.placeholder))
    ) || inputs.find(i => i.type === "text");

    return {
      user: userInput ? userInput.value.trim() : null,
      password: passwordInput.value,
      url: window.location.href
    };
  }

  // Also scan page-level for forms that submit via JS (not form submit event)
  function scanAllForms() {
    const forms = document.querySelectorAll("form");
    forms.forEach(form => {
      if (form.__bitguardListening) return;
      form.__bitguardListening = true;

      form.addEventListener("submit", (e) => {
        const creds = findLoginForm(form);
        if (creds && creds.password) {
          chrome.runtime.sendMessage({
            type: "LOGIN_DETECTED",
            payload: creds
          });
        }
      });
    });
  }

  // Catch forms that exist now
  scanAllForms();

  // Catch forms injected dynamically (SPAs)
  const observer = new MutationObserver(() => scanAllForms());
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // Also listen for click on submit buttons (some forms skip submit event)
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("button[type=submit], input[type=submit]");
    if (!btn) return;
    const form = btn.closest("form");
    if (!form) return;
    const creds = findLoginForm(form);
    if (creds && creds.password) {
      chrome.runtime.sendMessage({
        type: "LOGIN_DETECTED",
        payload: creds
      });
    }
  }, true);
})();

window.addEventListener("message", async (event) => {
  // Only allow same window messages
  if (event.source !== window) return;

  // IMPORTANT: Restrict origin (DO NOT use "*")
  if (event.origin !== "http://127.0.0.1:3000") return;

  if (event.data?.type === "REQUEST_AES_KEY") {

    try {
      const response = await chrome.runtime.sendMessage({
        type: "EXPORT_AES_KEY"
      });

      if (response?.success) {
        window.postMessage(
          {
            type: "VAULT_AES_KEY",
            keyBase64: response.keyBase64
          },
          "http://127.0.0.1:3000"   // restrict target origin
        );
      }

    } catch (err) {
      console.error("Failed to get AES key:", err);
    }
  }
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "GLOBAL_AES_KEY") {
    window.postMessage({
      type: "GLOBAL_AES_KEY",
      keyBase64: message.keyBase64
    }, "*");
  }
});
