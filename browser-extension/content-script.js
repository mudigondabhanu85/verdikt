// Mirrors backend/app/agents/macro.py's _RECORDER_INIT_SCRIPT exactly —
// same cssPath() selector-generation, same event set (input, click), same
// step shape ({action, selector, value, input_type}) — so a macro
// recorded here and one recorded by the in-app Playwright recorder are
// byte-for-byte the same JSON shape once field-role inference runs (see
// popup.js's applyFieldRoleInference(), which mirrors macro.py's
// _infer_field_roles()).

(() => {
  if (window.__verdiktContentScriptInstalled) return;
  window.__verdiktContentScriptInstalled = true;

  function cssPath(el) {
    if (el.id) return "#" + CSS.escape(el.id);
    if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name.replace(/"/g, '\\"') + '"]';
    let path = [];
    let node = el;
    while (node && node.nodeType === 1 && path.length < 6) {
      let selector = node.tagName.toLowerCase();
      if (node.parentElement) {
        const siblings = Array.from(node.parentElement.children).filter(
          (c) => c.tagName === node.tagName
        );
        if (siblings.length > 1) {
          selector += ":nth-of-type(" + (siblings.indexOf(node) + 1) + ")";
        }
      }
      path.unshift(selector);
      node = node.parentElement;
    }
    return path.join(" > ");
  }

  function recordStep(step) {
    chrome.runtime.sendMessage({ type: "verdikt-macro-step", step });
  }

  document.addEventListener(
    "input",
    (e) => {
      const el = e.target;
      if (!el || !el.tagName) return;
      if (el.tagName !== "INPUT" && el.tagName !== "TEXTAREA" && el.tagName !== "SELECT") return;
      const type = (el.type || "text").toLowerCase();
      const isSecret = type === "password";
      recordStep({
        action: "fill",
        selector: cssPath(el),
        value: isSecret ? null : el.value,
        input_type: type,
      });
    },
    true
  );

  document.addEventListener(
    "click",
    (e) => {
      const el = e.target.closest("button, a, input[type=submit], input[type=button]");
      if (!el) return;
      recordStep({
        action: "click",
        selector: cssPath(el),
        value: null,
        input_type: null,
      });
    },
    true
  );
})();
