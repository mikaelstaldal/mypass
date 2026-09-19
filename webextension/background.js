// Background script for the MyPass Firefox extension.
//
// Holds the native-messaging port to `mypass-browser-host` and drives the fill
// flow, plus — when the user has granted the optional permissions for it — the
// HTTP-authentication flow at the bottom of this file. Contains no crypto and
// stores no secrets at rest: credentials live in function/Map scope only for as
// long as a fill is in flight, and nothing is written to browser.storage, the
// clipboard, or the DOM by this script.

const HOST = "nu.staldal.mypass";

// One long-lived port per background script so the host process — and its
// in-memory unlock cache — survives across fills (§4.1, §4.3). A fresh port
// per request would spawn a new host and re-prompt every time.
let port = null;
let nextId = 1;
const pending = new Map(); // request id -> {resolve, reject}

// Per-tab matching entries (passwords included) waiting for the user to pick
// one in the popup. Held only between a multi-match query and the pick/close.
const pendingByTab = new Map();

function ensurePort() {
  if (port) return port;
  port = browser.runtime.connectNative(HOST);
  port.onMessage.addListener((msg) => {
    const waiter = pending.get(msg.id);
    if (waiter) {
      pending.delete(msg.id);
      waiter.resolve(msg);
    }
  });
  port.onDisconnect.addListener((p) => {
    const error =
      (p.error && p.error.message) ||
      (browser.runtime.lastError && browser.runtime.lastError.message) ||
      "native host disconnected";
    port = null;
    for (const [, waiter] of pending) waiter.reject(new Error(error));
    pending.clear();
  });
  return port;
}

// Send a request and resolve with the matching response (matched by id).
function send(message) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    try {
      ensurePort().postMessage(Object.assign({ id }, message));
    } catch (e) {
      pending.delete(id);
      reject(e);
    }
  });
}

function originForTab(tab) {
  try {
    // The origin is taken from the tab's own URL, never from anything the
    // page reports (§5.1 step 2, §9).
    return new URL(tab.url).origin;
  } catch (e) {
    return null;
  }
}

async function activeTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function errorMessage(resp) {
  switch (resp.code) {
    case "invalid-origin":
      return "This page is not an https login page.";
    case "no-match":
      return "No matching login in your vault.";
    case "unlock-cancelled":
      return "Unlock cancelled.";
    case "locked":
      return "The vault is locked.";
    case "scrypt-failed":
      return "Could not unlock the vault (wrong passphrase?).";
    case "db-missing":
      return "No vault file found.";
    default:
      return resp.message || "The MyPass host reported an error.";
  }
}

// Inject the fill script (top-level frame only) and hand it the credential.
// The credential exists only as arguments here and is dropped when this
// function returns (§5.1 step 6). Returns what the popup should render, so a
// page the script cannot reach becomes a message rather than a rejection the
// popup would have to guess at.
async function fillTab(tabId, entry) {
  let result;
  try {
    await browser.tabs.executeScript(tabId, { file: "/fill.js" });
    result = await browser.tabs.sendMessage(tabId, {
      type: "mypass-fill",
      username: entry.username,
      password: entry.password,
    });
  } catch (e) {
    // Nothing fillable here: an error page, a viewer, a load still stalled on
    // an HTTP-authentication dialog — none of them run a content script.
    setBadge(tabId, false);
    return { error: "Nothing to fill on this page: " + e.message };
  }
  setBadge(tabId, result && result.filledPassword);
  return { filled: result, name: entry.name };
}

function setBadge(tabId, ok) {
  if (typeof tabId !== "number" || tabId < 0) return; // not tied to a tab
  const text = ok ? "✓" : "!";
  const color = ok ? "#2e7d32" : "#c62828";
  browser.browserAction.setBadgeText({ tabId, text });
  browser.browserAction.setBadgeBackgroundColor({ tabId, color });
  setTimeout(() => browser.browserAction.setBadgeText({ tabId, text: "" }), 3000);
}

// The core flow, returning a plain object the popup can render. Passwords are
// never put in the returned object — only name/username for the chooser.
async function fillFlow() {
  const tab = await activeTab();
  if (!tab) return { error: "No active tab." };

  // An HTTP-authentication challenge held for this tab is what the popup was
  // opened for; it is about the browser's own prompt, not about the page, so
  // it takes precedence over anything fillable in the document.
  const challenge = pendingAuthByTab.get(tab.id);
  if (challenge) {
    // Held for a locked vault: the challenge is waiting for the user to open
    // it, not to choose. `unlocking` means pinentry is already up — this popup
    // is a second one, opened over it, and must not start another unlock.
    if (challenge.locked) {
      return {
        authLocked: true,
        unlocking: challenge.unlocking,
        host: challenge.host,
        realm: challenge.realm,
      };
    }
    return {
      authChoices: challenge.entries.map((e) => ({
        name: e.name,
        username: e.username,
      })),
      host: challenge.host,
      realm: challenge.realm,
    };
  }

  const origin = originForTab(tab);
  if (!origin) return { error: "This page has no fillable origin." };

  let resp;
  try {
    resp = await send({ type: "get-logins", origin });
  } catch (e) {
    return { error: "Cannot reach the MyPass host: " + e.message };
  }
  if (resp.type === "error") {
    return { error: errorMessage(resp), code: resp.code };
  }

  const entries = resp.entries || [];
  if (entries.length === 0) return { error: "No matching login." };
  if (entries.length === 1) return fillTab(tab.id, entries[0]);

  // More than one match: keep them for the popup to choose from.
  pendingByTab.set(tab.id, entries);
  return {
    choices: entries.map((e) => ({ name: e.name, username: e.username })),
  };
}

async function pick(tabId, name) {
  const entries = pendingByTab.get(tabId);
  pendingByTab.delete(tabId);
  if (!entries) return { error: "Selection expired; try again." };
  const entry = entries.find((e) => e.name === name);
  if (!entry) return { error: "Selection not found." };
  return fillTab(tabId, entry);
}

// The user picked an entry for the HTTP-authentication challenge this tab is
// waiting on. The credential goes straight back to the held request; it is
// never returned to the popup.
async function pickAuth(tabId, name) {
  const challenge = pendingAuthByTab.get(tabId);
  if (!challenge || !challenge.entries) {
    return { error: CHALLENGE_GONE };
  }
  const entry = challenge.entries.find((e) => e.name === name);
  if (!entry) return { error: "Selection not found." };
  settleAuthChoice(tabId, entry);
  return { authFilled: true, name: entry.name, username: entry.username };
}

// Is the vault unlocked? `status` never prompts, so this is free to call.
async function vaultStatus() {
  let resp;
  try {
    resp = await send({ type: "status" });
  } catch (e) {
    return { error: "Cannot reach the MyPass host: " + e.message };
  }
  if (!resp || resp.type !== "status") return { error: "Unexpected reply from the MyPass host." };
  return { locked: resp.locked };
}

// Unlock ahead of any fill, so the passphrase is entered when the user chooses
// rather than when a fill needs it. The host prompts in pinentry, outside the
// browser, and releases no entry — this cannot return a credential.
async function unlockVault() {
  // A locked HTTP-auth challenge held for the active tab is waiting for
  // exactly this, so take that path instead: it keeps the challenge alive
  // across the pinentry dialog and answers it afterwards, where a bare
  // `unlock` would leave it to expire into Firefox's own dialog.
  const tab = await activeTab();
  const challenge = tab && pendingAuthByTab.get(tab.id);
  if (challenge && challenge.locked && !challenge.unlocking) {
    const result = await unlockAuth(tab.id);
    return result.error ? result : { locked: false };
  }

  let resp;
  try {
    resp = await send({ type: "unlock" });
  } catch (e) {
    return { error: "Cannot reach the MyPass host: " + e.message };
  }
  if (resp.type === "error") return { error: errorMessage(resp), code: resp.code };
  if (resp.type !== "status") return { error: "Unexpected reply from the MyPass host." };
  unlockOfferDeclined.clear(); // the user has shown they want the vault open
  // Still locked after a successful unlock means the host is configured not to
  // cache (`cache_minutes: 0`), so there was nothing to keep.
  return { locked: resp.locked };
}

async function lockVault() {
  let resp;
  try {
    resp = await send({ type: "lock" });
  } catch (e) {
    return { error: "Cannot reach the MyPass host: " + e.message };
  }
  if (!resp || resp.type !== "ok") return { error: "Unexpected reply from the MyPass host." };
  // Locking means nothing more is released, so a challenge still waiting on a
  // choice is declined too, credentials and all — it falls back to Firefox's
  // own dialog like any other challenge we do not answer. An unlock already
  // under way is no exception: the user asked for the vault shut.
  settleAllAuthChoices(false);
  return { locked: true };
}

browser.runtime.onMessage.addListener((msg) => {
  if (msg && msg.cmd === "fill-request") return fillFlow();
  if (msg && msg.cmd === "pick") return pick(msg.tabId, msg.name);
  if (msg && msg.cmd === "pick-auth") return pickAuth(msg.tabId, msg.name);
  if (msg && msg.cmd === "unlock-auth") return unlockAuth(msg.tabId);
  if (msg && msg.cmd === "status") return vaultStatus();
  if (msg && msg.cmd === "unlock") return unlockVault();
  if (msg && msg.cmd === "lock") return lockVault();
  return false;
});

// Context-menu entry routes through the same popup so multi-match selection
// has somewhere to render.
browser.menus.create({
  id: "mypass-fill",
  title: "Fill login with MyPass",
  contexts: ["page", "editable"],
});
browser.menus.onClicked.addListener((info) => {
  if (info.menuItemId === "mypass-fill") {
    browser.browserAction.openPopup().catch(() => {});
  }
});

// --- HTTP authentication (opt-in) ------------------------------------------
//
// Firefox's HTTP-auth prompt is browser chrome, not DOM, so it cannot be
// filled. Instead, with the optional permissions in `auth-permissions.js`
// granted, the 401 is answered before the prompt is shown and the prompt never
// appears. Declining to answer (returning `{}`) always falls back to it.
//
// Unlike the form fill, this has no user gesture behind it, so it is
// deliberately narrow: top-level document loads only (never a subresource or
// an iframe, so an embedded `<img>`/`<iframe>` cannot make the browser submit
// your credentials somewhere in the background), never a proxy challenge,
// never off a locked vault on its own — a page must not be able to summon a
// pinentry dialog — and only for an entry whose site is *exactly* the
// challenging host, so a subdomain someone else controls cannot silently
// collect the parent domain's password.
//
// When several entries match that host — separate realms under one domain,
// each with its own username — the challenge is held while the popup asks
// which one to use. Nothing is released until the user picks; closing the
// popup, or waiting too long, hands the challenge back to Firefox's dialog.
//
// The same hold answers a locked vault: instead of declining outright, the
// challenge waits while the popup offers to unlock. That keeps the rule the
// host enforces — a page load cannot summon a pinentry dialog — because what
// the page summons is the popup, which releases nothing; pinentry still takes
// a click. What it does cost is that the offer has to come before we can know
// whether we even have an entry for the site, since finding out requires the
// vault to be open. Any https site that returns 401 can therefore put the
// offer up, so a host whose offer went unanswered is not asked about again for
// `UNLOCK_OFFER_RETRY_MS`.

// Requests we have already answered once. A second challenge for the same id
// means the credentials were refused, and the user gets the native dialog.
const answeredAuth = new Set();

// The host is local and already unlocked on this path, so a round-trip is
// quick; if it is not, let the request proceed to the dialog rather than
// stalling the page load.
const AUTH_TIMEOUT_MS = 5000;

function withTimeout(promise) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(null), AUTH_TIMEOUT_MS)),
  ]);
}

// Ask the host for the entries releasable to this protection space.
//
// `get-logins-strict` is a different request from the one the form fill uses:
// it matches the host exactly rather than accepting a parent domain, it
// narrows that by the realm the challenge named, and it answers a locked vault
// with an error instead of prompting. All three guarantees therefore hold
// inside the host, on the same request that returns the credential — not as a
// separate check here that the vault could expire behind. A host too old to
// know the request type answers `error/internal`, which declines here rather
// than quietly falling back to looser matching. One too old to know the realm
// ignores it, which only ever widens the answer into the chooser.
async function lookupAuth(origin, realm) {
  let resp;
  try {
    resp = await send({ type: "get-logins-strict", origin, realm: realm || null });
  } catch (e) {
    return null;
  }
  // A locked vault is the one outcome worth reporting back rather than
  // declining on: it is the only one the user can still do something about
  // while the challenge waits.
  if (resp && resp.type === "error" && resp.code === "locked") {
    return { locked: true };
  }
  if (!resp || resp.type !== "logins") return null;
  const entries = resp.entries || [];
  return entries.length ? { entries } : null;
}

// How long a challenge may wait for the user to pick one of several matching
// entries before it falls through to Firefox's dialog. The popup closing ends
// the wait sooner; this only bounds a popup left open and forgotten.
const AUTH_CHOICE_TIMEOUT_MS = 60000;

// How long a challenge may wait once the user has clicked to unlock. It has to
// cover a passphrase being typed into pinentry and the deliberately slow KDF
// that follows, so it is much longer than the choice timeout — but it is only
// ever reached by a pinentry dialog left standing.
const AUTH_UNLOCK_TIMEOUT_MS = 3 * 60 * 1000;

// How long a host whose unlock offer went unanswered is left alone for.
const UNLOCK_OFFER_RETRY_MS = 5 * 60 * 1000;

const CHALLENGE_GONE =
  "That login prompt is no longer waiting; reload the page.";

// Challenges held while the popup asks which entry to use — or whether to
// unlock — keyed by tab. This is the one place a credential outlives a single
// function call, and it lives exactly as long as the prompt the user is
// looking at.
const pendingAuthByTab = new Map();

// Hosts we offered to unlock for and got no answer, and when. Not persisted:
// the throttle is about one browsing session's nagging, and writing site names
// to disk is not something this extension does.
const unlockOfferDeclined = new Map(); // hostname -> Date.now() of the decline

// Resolve the tab's held challenge with `entry`, or with null to decline it,
// and drop the credentials it was holding.
function settleAuthChoice(tabId, entry) {
  const challenge = pendingAuthByTab.get(tabId);
  if (!challenge) return;
  pendingAuthByTab.delete(tabId);
  clearTimeout(challenge.timer);
  // An unlock offer the user did not take up — dismissed, timed out, or
  // cancelled at pinentry — quiets that host for a while.
  if (challenge.offeredUnlock) {
    if (entry) unlockOfferDeclined.delete(challenge.hostname);
    else unlockOfferDeclined.set(challenge.hostname, Date.now());
  }
  challenge.settle(entry);
}

// Decline every held challenge. `onlyIdle` spares one whose unlock the user
// has already committed to: pinentry takes focus, which closes the popup, so
// the popup going away must not cancel the very thing it started.
function settleAllAuthChoices(onlyIdle) {
  for (const tabId of Array.from(pendingAuthByTab.keys())) {
    if (onlyIdle && pendingAuthByTab.get(tabId).unlocking) continue;
    settleAuthChoice(tabId, null);
  }
}

// Hold the challenge and open the popup to ask the user about it. `fields`
// says what is being asked: `entries` for a choice between them, or
// `locked` for an offer to unlock. Resolves with the entry to answer the
// challenge with, or null to let Firefox's dialog take over.
async function holdChallenge(details, url, fields) {
  const tabId = details.tabId;
  if (typeof tabId !== "number" || tabId < 0) return null;
  // The popup always belongs to the active tab, so it can only speak for a
  // challenge in that tab. One in a background tab gets Firefox's dialog,
  // which is tab-modal and waits there for the user anyway.
  const active = await activeTab();
  if (!active || active.id !== tabId) return null;

  settleAuthChoice(tabId, null); // an older challenge for this tab is moot
  let settle;
  const answer = new Promise((resolve) => {
    settle = resolve;
  });
  pendingAuthByTab.set(
    tabId,
    Object.assign(
      {
        requestId: details.requestId,
        entries: null,
        locked: false,
        unlocking: false,
        offeredUnlock: false,
        // Kept so an unlock later can look the entries up on exactly the
        // origin this challenge came from, scheme included.
        origin: url.origin,
        hostname: url.hostname.toLowerCase(),
        host: (details.challenger && details.challenger.host) || "",
        realm: details.realm || "",
        settle,
        timer: setTimeout(
          () => settleAuthChoice(tabId, null),
          AUTH_CHOICE_TIMEOUT_MS
        ),
      },
      fields
    )
  );

  try {
    await browser.browserAction.openPopup();
  } catch (e) {
    // No popup — another window has focus, say — means no way to ask.
    settleAuthChoice(tabId, null);
  }
  return answer;
}

// Several entries for one host: ask which.
function chooseAuthEntry(details, url, entries) {
  return holdChallenge(details, url, { entries });
}

// A locked vault: offer to open it, unless this host's last offer went
// unanswered recently.
function offerUnlock(details, url) {
  const declinedAt = unlockOfferDeclined.get(url.hostname.toLowerCase());
  if (declinedAt !== undefined && Date.now() - declinedAt < UNLOCK_OFFER_RETRY_MS) {
    return null;
  }
  return holdChallenge(details, url, { locked: true, offeredUnlock: true });
}

// The user clicked to unlock for the challenge this tab is holding. This is
// the one path that may prompt for the master passphrase off the back of a
// page load, and it runs only from that click.
//
// The reply may well go nowhere: pinentry takes focus, which closes the popup
// that sent this. So everything the outcome needs is done here — the challenge
// is answered, declined, or handed on to the chooser in a freshly opened
// popup — and the return value is only for a popup that happens to survive.
async function unlockAuth(tabId) {
  const challenge = pendingAuthByTab.get(tabId);
  if (!challenge || !challenge.locked) return { error: CHALLENGE_GONE };
  if (challenge.unlocking) return { error: "Already unlocking." };

  challenge.unlocking = true;
  clearTimeout(challenge.timer);
  challenge.timer = setTimeout(
    () => settleAuthChoice(tabId, null),
    AUTH_UNLOCK_TIMEOUT_MS
  );

  // One request does both the unlocking and the matching, so that nothing can
  // relock in between — with `cache_minutes: 0` something always would, since
  // the host drops its entries as soon as it has answered.
  let resp;
  try {
    resp = await send({
      type: "get-logins-strict-unlock",
      origin: challenge.origin,
      realm: challenge.realm || null,
    });
  } catch (e) {
    settleAuthChoice(tabId, null);
    return { error: "Cannot reach the MyPass host: " + e.message };
  }

  // pinentry can stand for minutes, and the challenge may not have survived
  // it: the tab navigated away, or the vault was locked from elsewhere. Drop
  // whatever came back rather than answering a challenge nobody is waiting on.
  if (pendingAuthByTab.get(tabId) !== challenge) return { error: CHALLENGE_GONE };

  if (!resp || resp.type !== "logins" || !(resp.entries || []).length) {
    settleAuthChoice(tabId, null);
    return {
      error: resp && resp.type === "error" ? errorMessage(resp) : "No matching login.",
    };
  }
  unlockOfferDeclined.clear(); // the vault is open; the throttle is moot

  const entries = resp.entries;
  if (entries.length === 1) {
    settleAuthChoice(tabId, entries[0]);
    return {
      authFilled: true,
      name: entries[0].name,
      username: entries[0].username,
    };
  }

  // Several realms under this host. The challenge stays held and turns into
  // the ordinary chooser — in a new popup, since pinentry closed the old one.
  challenge.locked = false;
  challenge.unlocking = false;
  challenge.entries = entries;
  // The offer was taken up, so dismissing the chooser that follows is not a
  // reason to stop offering for this host.
  challenge.offeredUnlock = false;
  clearTimeout(challenge.timer);
  challenge.timer = setTimeout(
    () => settleAuthChoice(tabId, null),
    AUTH_CHOICE_TIMEOUT_MS
  );
  // Only if the popup that called this did not survive pinentry: it is
  // awaiting this reply and will render the choices itself if it did.
  if (!popupOpen) {
    try {
      await browser.browserAction.openPopup();
    } catch (e) {
      // Nowhere to ask, and nobody left to render the choices, so do not
      // leave the page hanging on a chooser that will never appear.
      settleAuthChoice(tabId, null);
      return { error: "Could not open the chooser." };
    }
  }
  return {
    authChoices: entries.map((e) => ({ name: e.name, username: e.username })),
    host: challenge.host,
    realm: challenge.realm,
  };
}

// The popup opens a port for no other reason than to make its lifetime
// observable here: a challenge the user dismissed the popup on should reach
// Firefox's dialog at once rather than sitting out the timeout, and an unlock
// that has to reopen the popup afterwards needs to know whether it is gone.
// A challenge whose unlock is already running is spared the dismissal —
// pinentry closed that popup itself.
let popupOpen = false;

browser.runtime.onConnect.addListener((popupPort) => {
  if (popupPort.name !== "mypass-popup") return;
  popupOpen = true;
  popupPort.onDisconnect.addListener(() => {
    popupOpen = false;
    settleAllAuthChoices(true);
  });
});

async function provideCredentials(details) {
  if (details.isProxy) return {};
  if (details.type !== "main_frame") return {};
  if (answeredAuth.has(details.requestId)) {
    answeredAuth.delete(details.requestId);
    return {}; // refused — hand the challenge to Firefox's own dialog
  }

  let url;
  try {
    url = new URL(details.url);
  } catch (e) {
    return {};
  }
  // The scheme comes from the request URL (so the host's https-only rule
  // applies), the host from the challenger; they must agree.
  const challenger = details.challenger && details.challenger.host;
  if (!challenger || url.hostname.toLowerCase() !== challenger.toLowerCase()) {
    return {};
  }

  const found = await withTimeout(lookupAuth(url.origin, details.realm));
  if (!found) return {};

  // Neither a locked vault nor several entries for one host — different
  // realms, different usernames, which the challenge itself cannot tell apart
  // — is something to decline outright: ask instead. The request stays open
  // while the popup is up.
  let entry;
  if (found.locked) {
    entry = await offerUnlock(details, url);
  } else if (found.entries.length === 1) {
    entry = found.entries[0];
  } else {
    entry = await chooseAuthEntry(details, url, found.entries);
  }
  if (!entry) return {};

  answeredAuth.add(details.requestId);
  return {
    authCredentials: { username: entry.username, password: entry.password },
  };
}

// Tabs where we answered the challenge of the load now in flight. The badge
// cannot be set at that moment: a tab's badge is reset when the tab navigates,
// and this navigation is the one still going. It is set when the page is done
// loading instead.
const authFilledTabs = new Set();

function authCompleted(details) {
  if (!answeredAuth.delete(details.requestId)) return;
  // A 401 here means our credentials were refused and the user dealt with the
  // dialog themselves; only a request that went through was our doing.
  if (details.statusCode !== 401 && details.tabId >= 0) {
    authFilledTabs.add(details.tabId);
  }
}

function authFailed(details) {
  answeredAuth.delete(details.requestId);
  // The load we were asking about is gone — the user navigated away or stopped
  // it — so stop holding its credentials and waiting for an answer.
  const challenge = pendingAuthByTab.get(details.tabId);
  if (challenge && challenge.requestId === details.requestId) {
    settleAuthChoice(details.tabId, null);
  }
}

// An HTTP-auth fill is otherwise completely invisible — no dialog, no form
// that visibly changes — so the badge is the only sign it happened.
function badgeAuthFill(tabId, changeInfo) {
  if (changeInfo.status !== "complete") return;
  if (authFilledTabs.delete(tabId)) setBadge(tabId, true);
}

function forgetAuthTab(tabId) {
  authFilledTabs.delete(tabId);
  settleAuthChoice(tabId, null); // the tab that asked is gone
}

// Registration follows the permission, so revoking it in the options page (or
// in about:addons) takes effect at once, with no restart.
function syncAuthListeners(granted) {
  if (!granted) {
    // Before the API check below: the namespace disappears with the
    // permission, and this state must be dropped either way.
    answeredAuth.clear();
    authFilledTabs.clear();
    unlockOfferDeclined.clear();
    settleAllAuthChoices(false);
  }
  if (!browser.webRequest) return; // API absent until the permission is granted
  const registered = browser.webRequest.onAuthRequired.hasListener(provideCredentials);
  if (granted && !registered) {
    const filter = { urls: AUTH_PERMISSIONS.origins };
    browser.webRequest.onAuthRequired.addListener(provideCredentials, filter, ["blocking"]);
    browser.webRequest.onCompleted.addListener(authCompleted, filter);
    browser.webRequest.onErrorOccurred.addListener(authFailed, filter);
    browser.tabs.onUpdated.addListener(badgeAuthFill, { properties: ["status"] });
    browser.tabs.onRemoved.addListener(forgetAuthTab);
  } else if (!granted && registered) {
    browser.webRequest.onAuthRequired.removeListener(provideCredentials);
    browser.webRequest.onCompleted.removeListener(authCompleted);
    browser.webRequest.onErrorOccurred.removeListener(authFailed);
    browser.tabs.onUpdated.removeListener(badgeAuthFill);
    browser.tabs.onRemoved.removeListener(forgetAuthTab);
  }
}

async function refreshAuthListeners(attempt) {
  const granted = await browser.permissions.contains(AUTH_PERMISSIONS);
  // The webRequest namespace only exists while the permission is held; on a
  // fresh grant it can appear a moment after the event, so retry briefly
  // rather than leaving the feature dead until the next browser start.
  if (granted && !browser.webRequest) {
    if (attempt < 5) setTimeout(() => refreshAuthListeners(attempt + 1), 200);
    return;
  }
  syncAuthListeners(granted);
}

browser.permissions.onAdded.addListener(() => refreshAuthListeners(0));
browser.permissions.onRemoved.addListener(() => refreshAuthListeners(0));
refreshAuthListeners(0);
