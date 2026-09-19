# Changelog

## 0.8.0 (2026-09-19)

- Renamed the command, Rust crate, browser host, default vault/config paths, and
  Firefox extension branding from `pw` to **MyPass**. The browser host still
  accepts the former `PW_*` environment variables as compatibility aliases.

## 0.7.0 (2026-09-16)

- Password generation now rejects custom charsets containing duplicate Unicode
  scalar values, which would otherwise bias the generated passwords.

## 0.6.0 (2026-08-30)

- Password entries can name an **HTTP authentication realm**, so a host running
  several protection spaces matches unambiguously instead of falling to the
  chooser: `mypass add nas-admin root --url nas.example --realm "Admin Area"`. New
  optional `--realm` on `add` and `update` (it requires `--url`, and omitting it
  on `update` clears it, like the username), shown by `get` and `show`.

  Among the entries on a host, one naming the challenged realm wins outright;
  failing that, the entries naming *no* realm are used, since an untagged entry
  is a wildcard over its host — which every entry written before this is, so an
  existing vault behaves exactly as it did. An entry naming a *different* realm
  is never released, even when nothing else matched. Realms are compared as
  exact strings, as the protocol defines them. A form fill ignores the realm
  entirely: a login form belongs to no protection space.

  `mypass::exactly_matching_entries` takes the challenged realm as a new second
  argument; `mypass::update_keep_password` takes the realm alongside the url. The
  `realm` field is not serialized when absent, so a vault without one stays
  byte-identical to the pre-`realm` format, and the browser host's
  `get-logins-strict`/`get-logins-strict-unlock` requests carry an optional
  `realm`. New `mypass::validate_realm`.

- Firefox add-on: an **HTTP-authentication challenge that finds the vault
  locked** is now held open while the toolbar popup offers to unlock, instead
  of falling straight through to Firefox's own dialog — so the vault no longer
  has to be unlocked *before* navigating to the site. It is part of
  HTTP-authentication filling, which remains off until you grant its optional
  permissions; there is no separate switch.

  The rule the host enforces is unchanged: a page load cannot summon a
  `pinentry` dialog. What a page can summon is the popup, which releases
  nothing; `pinentry` appears only on the click of *Unlock and sign in*. Since
  MyPass cannot tell whether it has an entry for a site until the vault is open,
  the offer necessarily comes before that is known, so a host whose offer goes
  unanswered is not asked about again for five minutes.

- New `get-logins-strict-unlock` request on `mypass-browser-host`, sent only from
  that click: the exact-host matching of `get-logins-strict`, but permitted to
  unlock via `pinentry`. Unlocking and matching are one request so that no
  relock can slip between them — with `cache_minutes: 0` one always would,
  since the host drops its entries as soon as it has answered. A host too old
  to know the request type answers `error/internal`, which the extension
  declines; it never falls back to a looser rule.

- The add-on's permissions are unchanged, and it still stores nothing: the
  five-minute offer throttle lives in the background script's memory only.

- No change to the vault file format: the new `realm` field is optional and
  omitted when unset, so a vault holding no realms is byte-identical to one
  written by 0.5.0. An older `mypass` reading a vault that does hold realms ignores
  the field — and drops it if it writes the vault back.

## 0.5.0 (2026-08-29)

- Firefox add-on: an **HTTP-authentication challenge with several matching
  entries** — separate realms under one domain, each with its own username — is
  now answerable. The challenge is held while the toolbar popup opens and asks
  which entry to use, naming the challenging host and its realm; the credential
  goes from the background script straight back to the held request, so the
  popup still never sees a password. Closing the popup, a challenge in a
  background tab, or a minute with no answer hands the challenge back to
  Firefox's own dialog, as does a picked credential the server rejects.
  Previously such a challenge was declined outright, and the popup's chooser —
  which fills page forms — appeared to do nothing when used on it, since an
  HTTP-authentication prompt is browser chrome with no form to fill.

- Firefox add-on: a fill on a page that runs no content script (an error page,
  a viewer, a load stalled on an authentication dialog) now reports that
  instead of leaving the popup stuck on *Filling…*.

- No change to `mypass-browser-host`, the wire protocol or the vault format.

## 0.4.0 (2026-08-14)

- New `get-logins-strict` request on `mypass-browser-host`, used by the extension's
  HTTP-authentication path (which has no user gesture behind it). It differs
  from `get-logins` in two ways, both enforced in the host: the visited host
  must equal the entry's `url` host **exactly**, so a subdomain under someone
  else's control cannot silently collect a parent domain's password; and a
  locked vault is answered with a new `locked` error instead of a `pinentry`
  prompt, so the no-prompt guarantee holds on the same request that returns the
  credential rather than in a separate check the cache could expire behind.
  New library function `mypass::exactly_matching_entries` implements the match. A
  host too old to know the request type answers `error/internal`, which the
  extension declines — it never falls back to the looser rule.

- The toolbar popup can unlock and lock the vault on its own: a new `unlock`
  request makes `mypass-browser-host` prompt via `pinentry` and cache the decrypted
  vault without matching, reading or releasing any entry — strictly weaker than
  `get-logins`. It answers with the `status` payload, so a host configured with
  `cache_minutes: 0` truthfully reports itself still locked.

- The Firefox add-on can fill **HTTP authentication** (the browser's own
  username/password dialog) from the vault, answering the `401` before the
  dialog is shown. It is off by default: the `webRequest`/`webRequestBlocking`
  and host permissions it needs are optional and granted from the add-on's new
  options page (`about:addons` → *MyPass* → *Preferences*), and revocable there.
  Only top-level page loads on `https:` (or loopback) are answered, only while
  the vault is already unlocked, and only when exactly one entry matches;
  everything else falls through to the browser's dialog. No change to
  `mypass-browser-host` or the wire protocol.

## 0.3.0 (2026-06-14)

### Firefox web integration

- New `mypass-browser-host` binary: a Firefox native-messaging host that fills
  usernames and passwords into login forms **without the clipboard** and
  **without giving the browser the whole vault**. It prompts for the master
  passphrase via `pinentry` (outside the browser), decrypts in-process, and
  releases only an entry matching the visited site. It is **strictly
  read-only** — it never writes the vault.
- Which sites may receive an entry is set entirely from the CLI: the host
  releases an entry only to a site matching the entry's `url`, which requires
  the master passphrase to set. Only entries with a `url` are usable in the
  browser. A compromised browser cannot associate new sites, which is what
  keeps the host read-only.
- New `mypass install-browser` subcommand writes the native-messaging manifest(s),
  detecting the snap and non-snap Firefox layouts (overridable with
  `--snap`/`--no-snap`), and creates a default `~/.config/mypass/browser.json`.
  `--uninstall` removes the manifest(s).
- New `webextension/` Firefox add-on (MV2): a background script holding the
  native-messaging port, a toolbar popup that picks among multiple matches,
  and an on-demand fill script. It contains no crypto and stores no secrets.
- Library: `mypass::matching_entries` and `mypass::origin_hostname` match a site's
  origin to entry urls by the eTLD+1 rule (Public Suffix List), with
  IDNA normalization and https-only eligibility.
- New optional `url` field on entries (`mypass add --url` / `mypass update --url`),
  which the browser integration matches against the visited site; the entry
  `name` is never matched. It is omitted from the stored JSON when empty, so
  existing vaults stay byte-identical to the previous format.
- New `apparmor-profile-browser-host` template confining `mypass-browser-host` to
  read-only access (the vault and its config) plus launching `pinentry`.

### Other

- `mypass update <name> --keep-password` changes an entry's username and url while
  keeping its current password, for re-pointing or relabelling an entry without
  rotating the secret.

## 0.2.2 (2026-06-12)

- On startup `mypass` now disables core dumps and, on Linux, marks itself
  non-dumpable (which also blocks `ptrace` attaches from same-user processes),
  so a crash can no longer persist the derived key or decrypted vault to disk.
  Swap is still an OS concern — see the README security notes on encrypted
  swap.
- A password copied to the clipboard is now removed after a timeout (default
  20 seconds), instead of lingering indefinitely. `mypass` waits in the
  foreground and then overwrites the clipboard if it still holds the password;
  pressing ENTER removes it immediately (Ctrl-C exits without removing). To
  evict the password from the desktop clipboard manager the slot is
  overwritten with a single space rather than emptied. The new global
  `--clear-timeout <secs>` flag tunes the
  delay, and `--clear-timeout 0` restores the previous never-clear behaviour.
  Note that a clipboard *history* manager may retain its own copy that `mypass`
  cannot clear — see the README security notes.

## 0.2.1 (2026-06-11)

Filter out strange Unicode characters which can be used for spoofing.

## 0.2.0 (2026-06-11)

Complete rewrite. **The vault file format is unchanged** — existing vaults
keep working as-is, and the file remains recoverable with the standard
`scrypt` tool (`scrypt dec ~/mypass.scrypt`).

### Breaking CLI changes

- `--password-length`, `--password-charset` and `--input-password` are no
  longer global flags; they moved onto the `add`, `update` and `generate`
  subcommands (e.g. `mypass add example.com user --password-length 24`).
- The username argument of `add`/`update` is now optional.
- `remove` asks for confirmation; pass `--yes` to skip it (scripts).
- Error message texts have changed.

### New

- All cryptography is done in-process; the external `scrypt` binary is no
  longer needed (and is no longer looked up on `PATH`).
- The passphrase is prompted at most once per operation (twice for `init`),
  instead of up to three times.
- `--passphrase-stdin` for non-interactive use.
- `mypass get --show` prints the password instead of copying it to the clipboard
  (also available on `add`, `update` and `generate`).
- `mypass list [PATTERN]` filters entries; `list` shows which vault file is in
  use.
- `mypass export` prints the decrypted vault as JSON for backup/migration.
- A notice is printed whenever something is copied to the clipboard.

### Fixed

- Vault writes are now atomic, with the previous vault kept as
  `mypass.scrypt.bak`; a crash can no longer destroy the vault.
- The vault file is created with mode `0600` from the start (Unix).
- Secrets are zeroized in memory and redacted from debug output.
- Wrong passphrase, corrupt vault and missing file are now distinct, helpful
  errors instead of panics.
- `generate` validates the password length (1–1024) and charset (at least 2
  distinct characters) instead of panicking.
- Entry names and usernames are validated (no control characters, at most
  256 characters).
