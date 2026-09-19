// Fill script. Injected into the active tab's
// top-level frame on demand; it receives one credential by message, fills the
// login form, and reports which fields it found. It holds the credential only
// for the duration of the fill and writes nothing back out.

(function () {
  // executeScript may inject this file more than once; register the listener
  // only on the first injection so each fill is handled exactly once.
  if (window.__pwFillListenerInstalled) return;
  window.__pwFillListenerInstalled = true;

  browser.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.type !== "mypass-fill") return;
    return Promise.resolve(fill(msg.username, msg.password));
  });

  function isVisible(el) {
    if (el.disabled || el.readOnly) return false;
    const style = window.getComputedStyle(el);
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0"
    ) {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  // Set the value through the prototype's native setter and dispatch input and
  // change so React/Vue/Angular controlled inputs register the change rather
  // than overwriting it from their own state.
  const nativeSetter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value"
  ).set;

  function setValue(el, value) {
    el.focus();
    nativeSetter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function findPasswordField() {
    const fields = Array.from(
      document.querySelectorAll('input[type="password"]')
    ).filter(isVisible);
    return fields[0] || null;
  }

  // The nearest visible text/email/tel input that precedes the password field,
  // preferring one inside the same form.
  function findUsernameField(passwordEl) {
    const scope = passwordEl.form || document;
    const candidates = Array.from(
      scope.querySelectorAll(
        'input[type="text"], input[type="email"], input[type="tel"], input[type="username"], input:not([type])'
      )
    ).filter(isVisible);
    let nearest = null;
    for (const el of candidates) {
      const pos = passwordEl.compareDocumentPosition(el);
      if (pos & Node.DOCUMENT_POSITION_PRECEDING) {
        nearest = el; // candidates are in document order; keep the last preceding one
      }
    }
    return nearest;
  }

  function fill(username, password) {
    const passwordEl = findPasswordField();
    if (!passwordEl) {
      return { filledPassword: false, filledUsername: false };
    }
    setValue(passwordEl, password);
    let filledUsername = false;
    if (username) {
      const usernameEl = findUsernameField(passwordEl);
      if (usernameEl) {
        setValue(usernameEl, username);
        filledUsername = true;
      }
    }
    return { filledPassword: true, filledUsername };
  }
})();
