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
  observer.observe(document.body, { childList: true, subtree: true });

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

// ── Receive messages from popup for password filling ─────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === "fillPassword" && typeof msg.password === "string") {
    const inputs = Array.from(document.querySelectorAll('input[type="password"]'));
    if (inputs.length > 0) {
      const input = inputs[0];
      input.focus();
      input.value = msg.password;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }
});
