# MyPass — a command line password manager

`mypass` keeps your passwords in a single encrypted file (`~/mypass.scrypt` by
default). All cryptography happens in-process; there are no runtime
dependencies on external programs.

## Installation

```sh
cargo install --path .
```

## Quick start

```sh
mypass init                      # create an empty vault at ~/mypass.scrypt
mypass add github.com mikael     # generate a password for an entry, copy it to the clipboard
mypass get github.com            # copy the password to the clipboard again
mypass list                      # show all entries
```

## Commands

| Command                                     | Description                                                                                                    |
|---------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| `mypass init`                               | Create a new empty vault. Asks for the passphrase twice.                                                       |
| `mypass get <name> [--show]`                | Copy the password to the clipboard, or print it with `--show`. Prints the username first, if there is one.     |
| `mypass list [PATTERN]`                     | List entries, optionally filtered by a case-insensitive substring of the name.                                 |
| `mypass add <name> [username] [options]`    | Add an entry. The password is generated (and copied to the clipboard) unless `--input-password` is given.      |
| `mypass update <name> [username] [options]` | Replace the username and password of an existing entry, or just the username/url/realm with `--keep-password`. |
| `mypass remove <name> [--yes]`              | Remove an entry, after confirmation (`--yes` skips it).                                                        |
| `mypass generate [options]`                 | Generate a password without storing it.                                                                        |
| `mypass export`                             | Print the decrypted vault as JSON on stdout, for backup or migration.                                          |
| `mypass install-browser [--uninstall]`      | Install (or remove) the Firefox native-messaging manifest for the browser integration. See below.              |

Options for `add`, `update` and `generate`:

- `--password-length <n>` — length of the generated password (default 16)
- `--password-charset <chars>` — characters to generate from; duplicate Unicode
  scalar values are rejected (default: letters, digits and `-`)
- `--input-password` — type the password instead of generating one
  (`add`/`update` only)
- `--url <url>` — the site this entry is for, used by the Firefox integration
  when the entry name is not the hostname (`add`/`update` only); omitting it on
  `update` clears it, like the username
- `--realm <realm>` — the HTTP authentication realm on that site this entry is
  for, when the site runs more than one (`add`/`update` only). Requires
  `--url`, and omitting it on `update` clears it
- `--keep-password` — on `update`, keep the existing password and change only
  the username, url and realm (`update` only)
- `--show` — print the password to stdout instead of copying it to the
  clipboard

Global options:

- `--file <path>` — use another vault file than `~/mypass.scrypt`
- `--passphrase-stdin` — read the passphrase as a single line from stdin
  instead of prompting; for scripts and other non-interactive use
- `--clear-timeout <secs>` — how long a copied password stays on the
  clipboard before `mypass` clears it (default 20). `mypass` waits this long, then
  clears the clipboard unless you have copied something else in the meantime;
  press ENTER to clear immediately, or Ctrl-C to exit without clearing. Use
  `0` to leave the clipboard untouched (the old behaviour)

The *username* is a free-form label stored alongside the password; it may be
omitted. Generated passwords use a cryptographically secure random number
generator (ChaCha20, OS-seeded) without modulo bias.

## Firefox integration

`mypass` can fill usernames and passwords into login forms in Firefox **without
using the clipboard** and **without handing Firefox the whole vault**. A
companion binary, `mypass-browser-host`, decrypts the vault in-process, releases
only the single entry matching the site you are on, and prompts for the master
passphrase in a `pinentry` dialog *outside* the browser. Only entries with a
`url` set are used in the browser: set the site explicitly with
`mypass add <name> --url github.com` (or `mypass update <name> --url …`). An entry's
`name` is never matched against the visited site, so it can be anything you
like — useful when you keep two accounts on one site.

**Origin matching** uses a layered rule: an entry matches a request for
`https://login.example.co.uk` when the host part of its `url`
equals the request hostname exactly (`login.example.co.uk`) or is a parent
domain at a label boundary (`example.co.uk`), up to but not including the
registrable domain determined by the Public Suffix List — so a `url` of
`co.uk` or `com` never matches. Matching is case-insensitive and
IDNA/punycode-normalized. Only `https:` origins are eligible (plus
`http://localhost` and `http://127.0.0.1` for local development).

The browser host is **strictly read-only**: it never writes the vault. Which
sites may receive an entry is decided by you, from the CLI: the host releases
an entry only to a site that matches the entry's `url`, which is
set only with the master passphrase in a terminal:

```sh
mypass add github.com alice --url github.com      # declare the site with --url
mypass add work-github alice --url github.com     # name can be anything; the url decides the match
mypass update work-github --url gitlab.com --keep-password   # re-point it, password unchanged
mypass add nas-admin root --url nas.example --realm "Admin Area"   # one realm on a host
```

A compromised browser therefore cannot make the host release an entry for a
site you never associated with it — only you can, with the master passphrase.

Setup:

```sh
mypass install-browser          # writes the native-messaging manifest + default config
```

Then load the add-on in `webextension/` (see `webextension/README.md` for
temporary loading during development and signing for permanent installation).
On a login page, click the toolbar button or press `Ctrl+Alt+L`.

The toolbar popup also has an **Unlock** button (**Lock** once open). It
prompts for the master passphrase in `pinentry` and caches the decrypted vault
in the host for `cache_minutes`, but fills nothing and releases no entry, so
you can open the vault when it suits you rather than when a fill needs it.

Behaviour is configured in `~/.config/mypass/browser.json`:

```json
{"file": "~/mypass.scrypt", "cache_minutes": 10}
```

- `cache_minutes` — how long a decrypted vault stays in the host's memory
  before it re-prompts (`0` re-prompts every time).

### HTTP authentication (opt-in)

The add-on can also answer a site's **HTTP authentication** challenge — the
browser's own username/password dialog — from the vault. Firefox's prompt is
browser chrome rather than page content, so nothing can type into it; instead
the `401` is answered before the prompt is shown, and it never appears.

This needs permission to see requests to all sites, so it is **off by default**
and is not part of the install-time permissions. Turn it on in `about:addons` →
*MyPass* → *Preferences*. A challenge is then answered only when it is a top-level
page load (never an image, script or iframe), on `https:` (or loopback) and not
a proxy, and at least one entry matches the site. Anything else falls through to
the browser's dialog, and credentials the server rejects are never retried.

A site can run several realms — separate protection spaces, each with its own
username — under one host, which the host part alone cannot tell apart. Name
the realm on the entry and the match is unambiguous:

```sh
mypass add nas-admin root  --url nas.example --realm "Admin Area"
mypass add nas-wiki  alice --url nas.example --realm "Wiki"
```

Among the entries on a host, one naming the challenged realm wins outright; if
none does, the entries naming *no* realm are used, since an untagged entry is a
wildcard over its host — which is what every entry written before this existed
is, so an unrealmed vault behaves exactly as it did. An entry naming a
*different* realm is never released, even when nothing else matches: being told
the credential belongs to another protection space is reason enough to withhold
it. Realms are compared as exact strings, as the protocol defines them — an
opaque quoted string, not a case-insensitive token. A form fill ignores the
realm entirely: a login form belongs to no protection space.

When several entries still match — two untagged entries on one host, say — the
toolbar popup opens and asks, naming the host and the realm. The page load
waits for the answer, and nothing is released until you pick one; closing the
popup (or leaving it a minute) hands the challenge back to the browser's own
dialog. A challenge in a background tab is never asked about — the popup speaks
for the active tab only — so that one gets the browser's dialog too.

Because nothing the user did triggers it, this path is **stricter than a form
fill in two further ways**, both enforced by the host rather than the browser,
on the same request that returns the credential:

- **The site must match exactly.** A form fill accepts a parent domain, so an
  entry for `example.com` fills on `www.example.com` — reasonable when you are
  looking at the page and clicked to fill it. Here it is not: a subdomain
  someone else controls (a dangling CNAME, shared hosting, one tenant of a
  multi-tenant apex) could otherwise collect the parent domain's password with
  no dialog to notice. This also matches how HTTP authentication scopes
  credentials itself — a protection space is one origin, never a domain tree.
- **A locked vault is never unlocked behind your back.** The request the
  extension sends (`get-logins-strict`) is answered with `locked` instead of a
  passphrase prompt, so no page load can make a `pinentry` dialog appear.
  Unlock deliberately, from the toolbar popup.

So the popup's **Unlock** button is the tidiest way in: unlock once, and
HTTP-auth sites then open with no interruption at all until the host's cache
expires. You do not have to think that far ahead, though — see below.

#### Offering to unlock from a challenge

Having to unlock *before* navigating would be the awkward part of the above, so
a challenge that finds the vault locked is **held open** — the same mechanism
that holds one while the chooser is up — and the popup offers to unlock,
instead of the challenge falling straight through to the browser's dialog.

The passphrase prompt is still yours to raise: what a page can summon is the
popup, which releases nothing, and `pinentry` appears only when you click
*Unlock and sign in*. The click sends a third request type,
`get-logins-strict-unlock`: exact matching as above, but permitted to prompt,
with the unlocking and the matching in one request so nothing can relock in
between (with `cache_minutes: 0` something always would). If several entries
then match, the ordinary chooser follows in a freshly opened popup —
`pinentry` taking focus closes the one that started it.

What it costs: until the vault is open MyPass cannot tell whether it has an entry
for the site at all, so the offer necessarily comes *before* that is known —
any `https:` site that returns `401` can put it up. To bound the nuisance, a
host whose offer goes unanswered is not asked about again for five minutes, and
the offer still requires a top-level load in the tab you are looking at.

### Security model

| Threat                                                                                                                              | Mitigation                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|-------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Malicious/XSS'd page harvesting autofill                                                                                            | No fill without a user gesture; no always-on content script; the page cannot trigger the extension. Opt-in HTTP-auth filling is the one gesture-less path, and answers only the challenging site itself (see the rows below).                                                                                                                                                                                                                                                  |
| Hidden `<img>`/`<iframe>` making the browser submit credentials in the background                                                   | HTTP-auth challenges are answered only for top-level page loads, so no subresource or embedded frame is ever answered — those get the browser's dialog.                                                                                                                                                                                                                                                                                                                        |
| Attacker-controlled subdomain of a site you have an entry for (takeover, shared hosting, multi-tenant apex) collecting its password | The HTTP-auth path matches the host exactly: `example.com` is not released to `evil.example.com`. Parent-domain matching applies only to a fill you asked for by clicking, on a page in front of you.                                                                                                                                                                                                                                                                          |
| Site provoking `401`s to pop the chooser up repeatedly                                                                              | The chooser only appears for a top-level load of a host you already have two or more entries for *in the challenged realm*, in the tab you are looking at, with the vault open — and it releases nothing until you click an entry. Dismissing it hands the challenge to the browser's dialog.                                                                                                                                                                                  |
| Site naming another site's realm to collect its credential                                                                          | The realm only ever narrows a match the host has already made exactly: an entry is released to `nas.example` and no other host, whatever realm is claimed. A realm is a label within a host, never across hosts.                                                                                                                                                                                                                                                               |
| Site provoking `401`s to nag you into unlocking                                                                                     | A host whose offer you dismiss is not asked about again for five minutes, and the offer needs a top-level load in the active tab. The offer itself releases nothing and reveals nothing about the vault — MyPass cannot tell whether it has an entry for the site until you unlock — and it is only ever an offer: the passphrase prompt takes your click.                                                                                                                     |
| Page trying to force a master-passphrase prompt                                                                                     | The HTTP-auth path sends `get-logins-strict`, which the host answers with `locked` rather than prompting, so no page load can raise a `pinentry` dialog. The guarantee lives in the host, on the request that would return the credential — not in a separate check the vault could expire behind. The one request that may prompt, `get-logins-strict-unlock`, is sent only from your click on the popup's own unlock button — a page can summon the popup, never `pinentry`. |
| Extension observing all browsing once HTTP-auth filling is on                                                                       | The permissions it needs are optional, granted by you at runtime, revocable in `about:addons`, and limited to `https:` plus loopback; without them the extension has no host permissions at all.                                                                                                                                                                                                                                                                               |
| Page spoofing its origin                                                                                                            | The origin is taken from the tab URL in the background script, never from page or content-script input.                                                                                                                                                                                                                                                                                                                                                                        |
| Phishing domain (`github.com.evil.example`)                                                                                         | Suffix matching at label boundaries bounded by the Public Suffix List — only `evil.example`'s own entries can match.                                                                                                                                                                                                                                                                                                                                                           |
| Rogue extension talking to the host                                                                                                 | `allowed_extensions` in the manifest pins `mypass@staldal.nu`; Firefox (and the snap portal) enforces it.                                                                                                                                                                                                                                                                                                                                                                      |
| Confined snap browser escaping to read the vault                                                                                    | The snap never gains direct access to `~/mypass.scrypt`; it can only ask the portal to launch the named host, gated by `allowed_extensions` and a one-time portal prompt.                                                                                                                                                                                                                                                                                                      |
| Compromised MyPass extension / browser process                                                                                      | Cannot read the vault file or passphrase; can only issue `get-logins` per origin, and only entries you associated with that site (by `name` or `url`, set from the CLI) are released. It cannot associate new sites (the host is read-only).                                                                                                                                                                                                                                   |
| Passphrase leakage via process metadata                                                                                             | The passphrase goes from pinentry into a zeroizing buffer and is consumed in-process — never in argv, the environment, or any subprocess. Zeroized after use.                                                                                                                                                                                                                                                                                                                  |
| Credentials at rest in the host                                                                                                     | Never written to disk; held in host memory only, bounded by `cache_minutes`, zeroized on lock or exit.                                                                                                                                                                                                                                                                                                                                                                         |
| Clipboard sniffers                                                                                                                  | The clipboard is not used anywhere in this flow.                                                                                                                                                                                                                                                                                                                                                                                                                               |

## File format and recovery

The vault is a standard [scrypt encrypted-data format](https://github.com/Tarsnap/scrypt/blob/master/FORMAT)
(version 0) file: scrypt KDF (`N=2^17, r=8, p=1` when writing), AES-256-CTR
encryption and HMAC-SHA256 integrity protection. Inside is a small JSON
document:

```json
{"version":1,"entries":[{"name":"github.com","username":"mikael","password":"..."}]}
```

Because the container is the standard format, the vault can always be
recovered without `mypass`, using the common
[scrypt](https://www.tarsnap.com/scrypt.html) tool:

```sh
scrypt dec ~/mypass.scrypt
```

which prints the JSON above. `mypass export` does the same from within `mypass`.

Writes are atomic (write-to-temp, fsync, rename), and the previous version of
the vault is kept as `mypass.scrypt.bak` next to it. A crash mid-write can never
leave a truncated vault. The temporary file is always `mypass.scrypt.tmp` next to
the vault, so a sandbox policy such as AppArmor only needs to allow
`mypass.scrypt`, `mypass.scrypt.tmp` and `mypass.scrypt.bak`.

## Security notes

- On Unix, the vault and its backup are created with mode `0600` from the
  start. **On Windows, file permissions are not restricted** — keep the vault
  in a directory only your user can read.
- A copied password is removed from the clipboard after `--clear-timeout`
  seconds (default 20; `mypass` waits in the foreground, or removes it at once when
  you press ENTER), and only if the clipboard still holds it, so anything you
  copy in the meantime is preserved. To reliably evict the password from the
  desktop clipboard manager the slot is overwritten with a single space rather
  than emptied, so the clipboard ends up holding a space, not nothing. **A
  clipboard history manager (GNOME extensions such
  as GPaste or Clipboard Indicator, KDE Klipper, the Windows clipboard
  history, third-party tools) may keep its own copy that `mypass` cannot reach** —
  disable history for sensitive copies, or use `--show` and pipe the password
  to a consumer you control. With `--clear-timeout 0` the password stays on
  the clipboard until something else overwrites it.
- Secrets are zeroized in memory when no longer needed, and never appear in
  debug output.
- On startup `mypass` disables core dumps, and on Linux marks itself non-dumpable
  (which also blocks `ptrace` attaches from other same-user processes), so a
  crash cannot persist the derived key or decrypted vault to disk. This does
  **not** protect against swap: while a secret is live, the kernel may page it
  out to swap, where zeroize-on-drop cannot reach it. On a machine that may
  swap, use **encrypted swap** (or disable swap with `swapoff`) to close this
  gap — it is an OS-level setting `mypass` cannot enforce itself.
- You can use the `apparmor-profile` file as a template for an Apparmor profile, you need to substitute 
  `${PATH_TO_EXECUTABLE}` with absolute paths. This has only been tested on Ubuntu Linux.
  `apparmor-profile-browser-host` is the matching template for the `mypass-browser-host`
  binary (see [Firefox integration](#firefox-integration)); it confines the host
  to reading the vault, reading its config, and launching `pinentry`.

## License

Copyright 2024-2026 Mikael Ståldal.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
