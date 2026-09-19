//! `mypass-browser-host` — the native-messaging host for the Firefox integration.
//! Started by Firefox (directly, or via the
//! WebExtensions XDG portal under the snap) when the extension connects, it
//! reads length-prefixed JSON requests on stdin and writes responses on
//! stdout. It owns all secret handling: it prompts for the master passphrase
//! via `pinentry`, decrypts the vault in-process, matches entries against the
//! requesting origin by their `url`, and returns only the matching entries. It
//! never lists the whole vault and never writes to it.

mod config;
mod debug_log;
mod pinentry;
mod protocol;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use mypass::{MyPassError, Passphrase, PasswordEntry};

use config::Config;
use protocol::{read_message, write_message, Login, Request, Response};

/// Reported in `status.version` and used to evolve the protocol.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum passphrase attempts before giving up with `scrypt-failed` (§6).
const MAX_UNLOCK_ATTEMPTS: u32 = 3;

fn main() -> ExitCode {
    harden_process();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mypass-browser-host: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let mut host = Host::new()?;
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    while let Some(message) = read_message(&mut stdin)? {
        let response = host.handle(&message);
        write_message(&mut stdout, &response)?;
        // With caching disabled, drop the decrypted entries as soon as the
        // request that needed them is answered.
        if host.cache_minutes == 0 {
            host.relock();
        }
    }
    Ok(())
}

/// Decrypted entries held in memory under the cache policy (§4.3). Zeroized on
/// drop because [`PasswordEntry`] is `ZeroizeOnDrop`.
struct Cache {
    entries: Vec<PasswordEntry>,
    expires_at: Instant,
}

struct Host {
    file: PathBuf,
    cache_minutes: u64,
    cache: Option<Cache>,
}

/// How a `get-logins*` request selects entries, and whether it may prompt.
#[derive(Clone, Copy, PartialEq)]
enum Strictness {
    /// `get-logins`: parent-domain matching up to the registrable domain, and
    /// may unlock via pinentry. The browser only sends it behind a user
    /// gesture, so both are the user's own doing.
    Normal,
    /// `get-logins-strict`: the visited host must equal the entry's `url` host
    /// exactly, and a locked vault is answered with `locked` rather than a
    /// prompt. For the browser's HTTP-authentication path, which answers a
    /// challenge with no user gesture behind it.
    Strict,
    /// `get-logins-strict-unlock`: exact matching like [`Strictness::Strict`],
    /// but may unlock via pinentry. The extension sends it only from the click
    /// on its own unlock button, when a challenge is being held open for that
    /// answer — so the prompt is the user's doing, even though the challenge
    /// that occasioned it was not. Matching and unlocking are one request so
    /// that no relock can slip between them (with `cache_minutes: 0` one
    /// always would).
    StrictUnlock,
}

impl Strictness {
    /// Whether the visited host must equal the entry's `url` host exactly.
    fn exact(self) -> bool {
        self != Strictness::Normal
    }

    /// For the debug log.
    fn label(self) -> &'static str {
        match self {
            Strictness::Normal => "normal",
            Strictness::Strict => "strict",
            Strictness::StrictUnlock => "strict-unlock",
        }
    }
}

/// Why an unlock could not produce decrypted entries; each maps to a protocol
/// error code (§6).
enum UnlockError {
    Cancelled,
    ScryptFailed,
    DbMissing,
    Internal(String),
}

impl Host {
    fn new() -> anyhow::Result<Host> {
        let config = Config::load()?;
        debug_log::init(config.log_file());
        log_startup(&config);
        Ok(Host {
            file: config.vault_file(),
            cache_minutes: config.cache_minutes,
            cache: None,
        })
    }

    fn handle(&mut self, message: &[u8]) -> Vec<u8> {
        let request: Request = match serde_json::from_slice(message) {
            Ok(request) => request,
            Err(e) => {
                return Response::Error {
                    id: 0,
                    code: "internal",
                    message: format!("malformed request: {e}"),
                }
                .to_bytes()
            }
        };
        let id = request.id;
        if debug_log::enabled() {
            debug_log::log(&format!(
                "request id={id} type={:?} origin={:?}",
                request.typ.as_deref().unwrap_or("(missing)"),
                request.origin.as_deref().unwrap_or("(none)"),
            ));
        }
        match request.typ.as_deref() {
            Some("get-logins") => self.get_logins(id, &request, Strictness::Normal),
            Some("get-logins-strict") => self.get_logins(id, &request, Strictness::Strict),
            Some("get-logins-strict-unlock") => {
                self.get_logins(id, &request, Strictness::StrictUnlock)
            }
            Some("unlock") => self.unlock(id),
            Some("lock") => {
                self.relock();
                Response::Ok { id }.to_bytes()
            }
            Some("status") => Response::Status {
                id,
                locked: !self.is_unlocked(),
                version: VERSION,
            }
            .to_bytes(),
            other => Response::Error {
                id,
                code: "internal",
                message: format!("unknown request type {:?}", other.unwrap_or("(missing)")),
            }
            .to_bytes(),
        }
    }

    fn get_logins(&mut self, id: u64, request: &Request, strictness: Strictness) -> Vec<u8> {
        let Some(origin) = request.origin.as_deref() else {
            return error(id, "invalid-origin", "request has no origin");
        };
        // The hostname drives `url` matching. It comes from the tab's
        // origin, never from anything the page reports.
        let Some(hostname) = mypass::origin_hostname(origin) else {
            return error(id, "invalid-origin", format!("ineligible origin {origin}"));
        };

        debug_log::log(&format!(
            "get-logins eligible hostname={hostname} matching={} realm={:?} unlocked={}",
            strictness.label(),
            request.realm.as_deref().unwrap_or("(none)"),
            self.is_unlocked()
        ));
        // A strict request must never prompt: the browser sends it without a
        // user gesture, so a passphrase dialog here would be one a visited
        // page caused. Declining is not a race — nothing between this check
        // and the matching below can unlock the vault, because a host handles
        // one request at a time. `StrictUnlock` is the deliberate exception:
        // it is sent only after the user has clicked to unlock.
        if strictness == Strictness::Strict && !self.is_unlocked() {
            return error(id, "locked", "vault is locked");
        }
        if let Err(e) = self.ensure_unlocked() {
            debug_log::log("unlock failed");
            return unlock_error(id, e);
        }

        let entries = &self.cache.as_ref().expect("unlocked").entries;
        // The realm narrows the exact match to one protection space. It is
        // ignored on the gesture-driven path: a login form belongs to no
        // protection space, so a realm there would only hide entries.
        let matched = if strictness.exact() {
            mypass::exactly_matching_entries(&hostname, request.realm.as_deref(), entries)
        } else {
            mypass::matching_entries(&hostname, entries)
        };
        debug_log::log(&format!(
            "unlocked: {} entries, {} match {hostname}",
            entries.len(),
            matched.len()
        ));
        if matched.is_empty() {
            return error(id, "no-match", format!("no entry matches {hostname}"));
        }

        // Release every entry whose `url` matches the visited site.
        let selected: Vec<Login> = matched.iter().map(|e| Login::from(*e)).collect();
        Response::Logins {
            id,
            entries: selected,
        }
        .to_bytes()
    }

    /// Unlock on request, so the user can enter the passphrase when it suits
    /// them rather than when a fill needs it. It releases nothing: no entry is
    /// read or returned, which keeps it strictly weaker than `get-logins`.
    fn unlock(&mut self, id: u64) -> Vec<u8> {
        if let Err(e) = self.ensure_unlocked() {
            debug_log::log("unlock failed");
            return unlock_error(id, e);
        }
        // Reported after the unlock, so with `cache_minutes: 0` this correctly
        // says `locked` — the cache expires the instant it is set, and `run`
        // drops the entries again as soon as this response is written.
        Response::Status {
            id,
            locked: !self.is_unlocked(),
            version: VERSION,
        }
        .to_bytes()
    }

    fn is_unlocked(&self) -> bool {
        self.cache
            .as_ref()
            .is_some_and(|c| Instant::now() < c.expires_at)
    }

    /// Ensure the cache holds non-expired decrypted entries, unlocking via
    /// pinentry if needed, and (re)set the lock timer on success.
    fn ensure_unlocked(&mut self) -> Result<(), UnlockError> {
        if !self.is_unlocked() {
            self.relock(); // zeroize any expired entries first
            let entries = self.decrypt()?;
            self.cache = Some(Cache {
                entries,
                expires_at: Instant::now(),
            });
        }
        if let Some(cache) = &mut self.cache {
            cache.expires_at = Instant::now() + Duration::from_secs(self.cache_minutes * 60);
        }
        Ok(())
    }

    /// Prompt for the passphrase and decrypt, retrying up to
    /// [`MAX_UNLOCK_ATTEMPTS`] on a wrong passphrase.
    fn decrypt(&self) -> Result<Vec<PasswordEntry>, UnlockError> {
        if !self.file.exists() {
            return Err(UnlockError::DbMissing);
        }
        let desc = format!("Unlock {}", self.file.display());
        let mut error_hint: Option<&str> = None;
        for attempt in 1..=MAX_UNLOCK_ATTEMPTS {
            debug_log::log(&format!("pinentry: prompting (attempt {attempt})"));
            let pin = match pinentry::get_passphrase(&desc, "Passphrase:", error_hint) {
                Ok(pin) => pin,
                Err(pinentry::Error::Cancelled) => {
                    debug_log::log("pinentry: cancelled");
                    return Err(UnlockError::Cancelled);
                }
                Err(pinentry::Error::Failed(m)) => {
                    debug_log::log(&format!("pinentry: failed: {m}"));
                    return Err(UnlockError::Internal(m));
                }
            };
            debug_log::log("pinentry: got passphrase, decrypting");
            let mut pin = pin;
            let passphrase = Passphrase::new(std::mem::take(&mut *pin));
            match mypass::list(&self.file, &passphrase) {
                Ok(entries) => {
                    debug_log::log("decrypt: success");
                    return Ok(entries);
                }
                Err(MyPassError::WrongPassphrase) => {
                    debug_log::log("decrypt: wrong passphrase");
                    error_hint = Some("Incorrect passphrase, try again");
                }
                Err(MyPassError::FileNotFound(_)) => return Err(UnlockError::DbMissing),
                Err(e) => return Err(UnlockError::Internal(e.to_string())),
            }
        }
        Err(UnlockError::ScryptFailed)
    }

    /// Drop and zeroize any cached entries.
    fn relock(&mut self) {
        self.cache = None;
    }
}

/// Log the version and the parts of the environment pinentry depends on. This
/// is the key diagnostic for the Firefox/snap case, where the native host is
/// launched by a portal that may strip `DISPLAY`/`WAYLAND_DISPLAY`/
/// `DBUS_SESSION_BUS_ADDRESS`, leaving pinentry unable to show or return a
/// usable dialog. No secret is involved. A no-op when logging is disabled.
fn log_startup(config: &Config) {
    if !debug_log::enabled() {
        return;
    }
    debug_log::log(&format!("=== mypass-browser-host {VERSION} starting ==="));
    debug_log::log(&format!(
        "config: vault={} cache_minutes={}",
        config.vault_file().display(),
        config.cache_minutes,
    ));
    for var in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "GPG_TTY",
        "TERM",
        "LANG",
        "PATH",
    ] {
        match std::env::var(var) {
            Ok(value) => debug_log::log(&format!("env {var}={value}")),
            Err(_) => debug_log::log(&format!("env {var}=(unset)")),
        }
    }
}

fn error(id: u64, code: &'static str, message: impl Into<String>) -> Vec<u8> {
    Response::Error {
        id,
        code,
        message: message.into(),
    }
    .to_bytes()
}

fn unlock_error(id: u64, e: UnlockError) -> Vec<u8> {
    match e {
        UnlockError::Cancelled => error(id, "unlock-cancelled", "passphrase entry cancelled"),
        UnlockError::ScryptFailed => error(id, "scrypt-failed", "could not decrypt the vault"),
        UnlockError::DbMissing => error(id, "db-missing", "no vault file"),
        UnlockError::Internal(m) => error(id, "internal", m),
    }
}

/// Best-effort process hardening mirroring the `mypass` binary: disable core dumps
/// so a crash cannot persist decrypted data, and mark the process
/// non-dumpable on Linux to block `ptrace` from same-user processes. Failures
/// are ignored (defense in depth, not a correctness requirement).
#[cfg(unix)]
fn harden_process() {
    // SAFETY: both calls take plain scalars and have no memory effects;
    // ignoring the result is intentional (best-effort hardening).
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);

        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

#[cfg(not(unix))]
fn harden_process() {}
