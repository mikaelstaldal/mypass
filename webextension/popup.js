// Popup UI. Asks the background script to
// run the fill flow and, when more than one entry matches, lets the user pick.
// It never sees passwords — only names and usernames — and stores nothing.

const statusEl = document.getElementById("status");
const listEl = document.getElementById("list");

// A port with no messages on it: the background script watches it disconnect
// so that an HTTP-authentication challenge waiting on a choice here falls
// through to Firefox's own dialog the moment this popup goes away.
browser.runtime.connect({ name: "mypass-popup" });

async function currentTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function showStatus(text, isError) {
  statusEl.textContent = text;
  statusEl.classList.toggle("error", !!isError);
}

function describeFill(result) {
  if (!result.filled) return "Done.";
  if (!result.filled.filledPassword) {
    return "No login form found on this page.";
  }
  return result.filled.filledUsername
    ? "Filled username and password."
    : "Filled password (no username field found).";
}

function clearList() {
  while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
}

// Send `cmd` for the picked entry and report what came back. Anything thrown
// on the way is shown too: the chooser has already been cleared away, so a
// silent failure here would leave the popup looking like nothing happened.
async function send(cmd, name) {
  const tab = await currentTab();
  try {
    return await browser.runtime.sendMessage({ cmd, tabId: tab.id, name });
  } catch (e) {
    return { error: "Error: " + e.message };
  }
}

async function choose(name) {
  showStatus("Filling…");
  clearList();
  const result = await send("pick", name);
  if (!result || result.error) {
    showStatus(result ? result.error : "No response.", true);
    return;
  }
  showStatus(describeFill(result), result.filled && !result.filled.filledPassword);
  setTimeout(() => window.close(), 900);
}

// The same chooser, for the HTTP-authentication challenge the background
// script is holding. The credential goes from there straight to the challenge;
// this popup never sees it, and there is no page to fill.
async function chooseAuth(name) {
  showStatus("Signing in…");
  clearList();
  const result = await send("pick-auth", name);
  if (!result || result.error) {
    showStatus(result ? result.error : "No response.", true);
    return;
  }
  showStatus(
    result.username ? "Signing in as " + result.username + "…" : "Signing in…"
  );
  setTimeout(() => window.close(), 900);
}

// One action button in the same list the chooser uses.
function renderAction(label, onClick) {
  const li = document.createElement("li");
  const button = document.createElement("button");
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = label;
  button.appendChild(name);
  button.addEventListener("click", onClick);
  li.appendChild(button);
  listEl.appendChild(li);
}

// The vault is locked and an HTTP-authentication challenge is being held open
// for it. Unlocking here is a click, which is what makes the passphrase prompt
// the user's own doing rather than the page's.
//
// The reply usually never arrives: pinentry takes focus and this popup is
// destroyed. The background script finishes the job either way — it fills the
// challenge, or reopens this popup with the chooser — so anything rendered
// below is a bonus for the case where the popup outlives the prompt.
async function unlockForAuth() {
  showStatus("Enter your passphrase in the pinentry window…");
  clearList();
  const result = await send("unlock-auth");
  if (!result || result.error) {
    showStatus(result ? result.error : "No response.", true);
    return;
  }
  if (result.authChoices && result.authChoices.length) {
    showStatus(describeChallenge(result) + " is asking for a login:");
    renderChoices(result.authChoices, chooseAuth);
    return;
  }
  showStatus(
    result.username ? "Signing in as " + result.username + "…" : "Signing in…"
  );
  setTimeout(() => window.close(), 900);
}

function renderChoices(choices, onPick) {
  for (const choice of choices) {
    const li = document.createElement("li");
    const button = document.createElement("button");
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = choice.name;
    button.appendChild(name);
    if (choice.username) {
      const user = document.createElement("span");
      user.className = "user";
      user.textContent = " — " + choice.username;
      button.appendChild(user);
    }
    button.addEventListener("click", () => onPick(choice.name));
    li.appendChild(button);
    listEl.appendChild(li);
  }
}

document.getElementById("settings").addEventListener("click", () => {
  browser.runtime.openOptionsPage();
  window.close();
});

// Unlock/lock the vault without filling anything. Unlocking here is what makes
// a later fill — or an HTTP-auth challenge, which never prompts on its own —
// happen without a passphrase dialog.
const vaultEl = document.getElementById("vault");

function renderVault(locked) {
  vaultEl.hidden = false;
  vaultEl.disabled = false;
  vaultEl.textContent = locked ? "Unlock" : "Lock";
  vaultEl.dataset.locked = locked ? "yes" : "";
}

vaultEl.addEventListener("click", async () => {
  const wasLocked = vaultEl.dataset.locked === "yes";
  vaultEl.disabled = true;
  if (wasLocked) {
    // pinentry takes focus, which closes this popup; the unlock still
    // completes in the background script.
    showStatus("Enter your passphrase in the pinentry window…");
  }
  const result = await browser.runtime.sendMessage({
    cmd: wasLocked ? "unlock" : "lock",
  });
  if (!result || result.error) {
    showStatus(result ? result.error : "No response from the MyPass host.", true);
    vaultEl.disabled = false;
    return;
  }
  renderVault(result.locked);
  if (!result.locked) {
    showStatus("Vault unlocked.");
  } else if (wasLocked) {
    showStatus("Unlocked, but this host does not cache it (cache_minutes 0).");
  } else {
    showStatus("Vault locked.");
  }
});

async function refreshVault() {
  const result = await browser.runtime.sendMessage({ cmd: "status" });
  if (result && !result.error) renderVault(result.locked);
}

// Name the protection space the challenge came from, so realms that share a
// host — which is exactly when this chooser appears — can be told apart.
//
// The realm is the server's own text, so it is stripped of control, bidi and
// zero-width characters and kept short: it must read as a label, and it must
// not be able to dress itself up as the rest of the sentence. It is rendered
// as text, never as markup.
function describeChallenge(result) {
  const host = result.host || "This site";
  const realm = (result.realm || "")
    .replace(
      /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g,
      ""
    )
    .trim()
    .slice(0, 60);
  return realm ? host + " “" + realm + "”" : host;
}

async function init() {
  let result;
  try {
    result = await browser.runtime.sendMessage({ cmd: "fill-request" });
  } catch (e) {
    showStatus("Error: " + e.message, true);
    return;
  }
  if (!result || result.error) {
    showStatus(result ? result.error : "No response from the MyPass host.", true);
    return;
  }
  if (result.filled) {
    showStatus(describeFill(result), !result.filled.filledPassword);
    setTimeout(() => window.close(), 900);
    return;
  }
  if (result.authChoices && result.authChoices.length) {
    showStatus(describeChallenge(result) + " is asking for a login:");
    renderChoices(result.authChoices, chooseAuth);
    return;
  }
  if (result.authLocked) {
    // A second popup opened over a pinentry dialog that is already up must not
    // start another unlock.
    if (result.unlocking) {
      showStatus("Enter your passphrase in the pinentry window…");
      return;
    }
    showStatus(
      describeChallenge(result) + " is asking for a login, and MyPass is locked."
    );
    renderAction("Unlock and sign in", unlockForAuth);
    return;
  }
  if (result.choices && result.choices.length) {
    showStatus("Choose a login:");
    renderChoices(result.choices, choose);
    return;
  }
  showStatus("Nothing to fill.", true);
}

refreshVault();
init();
