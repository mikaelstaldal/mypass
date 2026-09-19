// The optional permissions behind HTTP-authentication filling, shared by the
// background script and the options page (both load this file first).
//
// These are NOT requested at install time: without them the extension has no
// host permissions at all and can only touch a page after a user gesture. The
// user opts in from the options page, and can revoke at any time.
//
// The origins are also the webRequest filter, so an HTTP-auth challenge from
// any other scheme or host never reaches the extension and gets Firefox's own
// dialog. They mirror the host's eligibility rule (https, plus loopback for
// local development) — see `mypass::origin_hostname`.
const AUTH_PERMISSIONS = {
  permissions: ["webRequest", "webRequestBlocking"],
  origins: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
};
