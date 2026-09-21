//! # MyPass
//!
//! A command line password manager. All prompting, terminal and clipboard
//! handling lives here; the library never assumes a terminal.

use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clippers::Clipboard;
use dirs::home_dir;
use zeroize::Zeroizing;

use mypass::{Params, Passphrase, PasswordEntry, Secret};

mod tui;

const DEFAULT_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

#[derive(Parser)]
#[command(version, about = "MyPass — a command line password manager")]
struct Cli {
    /// The encrypted vault file, ~/mypass.scrypt by default
    #[arg(long, global = true)]
    file: Option<PathBuf>,

    /// Read the passphrase as a single line from stdin instead of prompting
    #[arg(long, global = true)]
    passphrase_stdin: bool,

    /// Seconds to keep a copied password on the clipboard before clearing it
    /// (cleared only if still unchanged); 0 leaves the clipboard untouched
    #[arg(long, global = true, default_value_t = 20)]
    clear_timeout: u64,

    /// Override the scrypt CPU/memory cost (log2 of N) when writing;
    /// intended for tests
    #[arg(long, global = true, hide = true)]
    scrypt_log_n: Option<u8>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Args)]
struct PasswordOptions {
    /// Type the password to save, instead of generating one
    #[arg(long)]
    input_password: bool,

    /// Length of the generated password
    #[arg(long, default_value_t = 16)]
    password_length: u32,

    /// Characters to use in the generated password
    #[arg(long, default_value = DEFAULT_CHARSET)]
    password_charset: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new empty vault
    Init {},

    /// Look up a password and copy it to the clipboard
    Get {
        /// The password entry
        name: String,
        /// Print the password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// List entries
    List {
        /// Only show entries whose name contains this (case-insensitive)
        pattern: Option<String>,
    },

    /// Add a password
    Add {
        /// The password entry
        name: String,
        /// Username (free-form label, may be omitted)
        username: Option<String>,
        /// Site this entry is for (e.g. github.com). Required for the entry to
        /// be used by the browser integration, which matches on url only
        #[arg(long)]
        url: Option<String>,
        /// HTTP authentication realm on that site, if it runs more than one
        #[arg(long, requires = "url")]
        realm: Option<String>,
        #[command(flatten)]
        password: PasswordOptions,
        /// Print the new password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// Update a password
    Update {
        /// The password entry
        name: String,
        /// Username (free-form label, may be omitted)
        username: Option<String>,
        /// Site this entry is for; omit to clear it (like the username)
        #[arg(long)]
        url: Option<String>,
        /// HTTP authentication realm on that site; omit to clear it
        #[arg(long, requires = "url")]
        realm: Option<String>,
        /// Keep the existing password, only changing the username, url and realm
        #[arg(long, conflicts_with = "input_password")]
        keep_password: bool,
        #[command(flatten)]
        password: PasswordOptions,
        /// Print the new password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// Remove a password
    Remove {
        /// The password entry
        name: String,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },

    /// Generate a password without storing it
    Generate {
        /// Length of the generated password
        #[arg(long, default_value_t = 16)]
        password_length: u32,

        /// Characters to use in the generated password
        #[arg(long, default_value = DEFAULT_CHARSET)]
        password_charset: String,

        /// Print the password to stdout instead of copying it
        #[arg(long)]
        show: bool,
    },

    /// Show all attributes of an entry except the password
    Show {
        /// The password entry
        name: String,
    },

    /// Print the decrypted vault as JSON, for backup or migration
    Export {},

    /// Install the Firefox native-messaging manifest for the browser host
    InstallBrowser {
        /// Remove the manifest(s) instead of writing them
        #[arg(long)]
        uninstall: bool,

        /// Deprecated: snap Firefox now uses the same standard path (no-op)
        #[arg(long, conflicts_with = "no_snap")]
        snap: bool,

        /// Deprecated: all Firefox variants use the same standard path (no-op)
        #[arg(long)]
        no_snap: bool,
    },
}

fn main() -> ExitCode {
    harden_process();
    run().unwrap_or_else(|err| {
        eprintln!("error: {err:#}");
        ExitCode::FAILURE
    })
}

/// Reverse-DNS name of the native-messaging host, used as the manifest
/// filename and its `name` field; must match the `connectNative` call in the
/// extension's background script.
const HOST_MANIFEST_NAME: &str = "nu.staldal.mypass";
/// The pinned extension ID (`browser_specific_settings.gecko.id`) allowed to
/// talk to the host.
const EXTENSION_ID: &str = "mypass@staldal.nu";

/// Install (or remove) the Firefox native-messaging manifest(s) so Firefox can
/// find `mypass-browser-host`, and create a default `~/.config/mypass/browser.json`.
fn install_browser(uninstall: bool, snap: bool, no_snap: bool) -> anyhow::Result<()> {
    let home = home_dir().context("cannot determine the home directory")?;

    if uninstall {
        for dir in uninstall_dirs(&home, snap, no_snap) {
            let path = dir.join(format!("{HOST_MANIFEST_NAME}.json"));
            match fs::remove_file(&path) {
                Ok(()) => println!("Removed {}", path.display()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).context(format!("cannot remove {}", path.display())),
            }
        }
        println!("The Firefox extension itself must be removed from about:addons.");
        return Ok(());
    }

    let host_path = host_binary_path()?;
    let manifest = native_messaging_manifest(&host_path)?;
    for dir in install_dirs(&home, snap, no_snap) {
        fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let path = dir.join(format!("{HOST_MANIFEST_NAME}.json"));
        fs::write(&path, &manifest).with_context(|| format!("cannot write {}", path.display()))?;
        println!("Wrote {}", path.display());
    }
    write_default_config(&home)?;

    if !host_path.exists() {
        eprintln!(
            "Note: host binary {} does not exist yet; install it alongside MyPass \
             before using the extension.",
            host_path.display()
        );
    }
    Ok(())
}

/// The absolute path to `mypass-browser-host`, expected next to the running `mypass`.
fn host_binary_path() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot determine the mypass executable path")?;
    // Resolve symlinks so the manifest points at the real binary; fall back to
    // the raw path if canonicalization fails (e.g. the file was moved).
    let exe = exe.canonicalize().unwrap_or(exe);
    let dir = exe
        .parent()
        .context("the mypass executable has no parent directory")?;
    Ok(dir.join("mypass-browser-host"))
}

/// The manifest JSON. `path` must be absolute.
fn native_messaging_manifest(host_path: &Path) -> anyhow::Result<String> {
    let path = host_path
        .to_str()
        .context("the host binary path is not valid UTF-8")?;
    if !host_path.is_absolute() {
        bail!("the host binary path {path} is not absolute");
    }
    let manifest = serde_json::json!({
        "name": HOST_MANIFEST_NAME,
        "description": "MyPass password manager",
        "path": path,
        "type": "stdio",
        "allowed_extensions": [EXTENSION_ID],
    });
    Ok(serde_json::to_string_pretty(&manifest)?)
}

/// The Firefox native-messaging directory.  Both snap and non-snap Firefox
/// read manifests from this standard location: the snap variant does so via
/// the XDG desktop portal, which checks the same path.
fn manifest_dir(home: &Path) -> PathBuf {
    home.join(".mozilla/native-messaging-hosts")
}

/// Where to write manifests.  All Firefox variants use the same standard
/// path; `--snap`/`--no-snap` are accepted for backwards compatibility but
/// have no effect on the destination.
fn install_dirs(home: &Path, _snap: bool, _no_snap: bool) -> Vec<PathBuf> {
    vec![manifest_dir(home)]
}

/// Where to look when removing manifests.
fn uninstall_dirs(home: &Path, _snap: bool, _no_snap: bool) -> Vec<PathBuf> {
    vec![manifest_dir(home)]
}

/// Create `~/.config/mypass/browser.json` with defaults, unless it already exists.
fn write_default_config(home: &Path) -> anyhow::Result<()> {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| home.join(".config"))
        .join("mypass");
    let path = dir.join("browser.json");
    if path.exists() {
        println!(
            "Config {} already exists; leaving it unchanged.",
            path.display()
        );
        return Ok(());
    }
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let config = serde_json::to_string_pretty(&serde_json::json!({
        "file": "~/mypass.scrypt",
        "cache_minutes": 10,
    }))?;
    write_private(&path, config.as_bytes())
        .with_context(|| format!("cannot write {}", path.display()))?;
    println!("Wrote default config {}", path.display());
    Ok(())
}

/// Write a file `0600` on Unix.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

/// Best-effort process hardening, run once before any secret is read.
///
/// Disables core dumps so a crash cannot persist the derived key or the
/// decrypted vault to disk, and on Linux marks the process non-dumpable,
/// which additionally blocks `ptrace` attaches from same-user processes.
/// This does not protect against swap; see the README on encrypted swap.
/// Failures are ignored: this is defense in depth, not a correctness
/// requirement, and the kernel may forbid these on some configurations.
#[cfg(unix)]
fn harden_process() {
    // SAFETY: both calls take plain scalars/POD and have no memory effects;
    // ignoring the return value is intentional (best-effort hardening).
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

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();

    let file = cli.file.unwrap_or_else(|| {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mypass.scrypt")
    });
    let params = Params {
        log_n: cli.scrypt_log_n.unwrap_or(Params::default().log_n),
        ..Params::default()
    };
    let clear_timeout = cli.clear_timeout;

    // Holds the value copied to the clipboard, if any, so it can be cleared
    // after `clear_timeout` once the command has otherwise finished.
    let mut pending_clear: Option<Zeroizing<String>> = None;

    match cli.command {
        Some(Commands::Init {}) => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, true)?;
            mypass::init(&file, &passphrase, &params)?;
            println!("Initialized empty vault at {}", file.display());
        }
        Some(Commands::Get { name, show }) => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let entry = mypass::get(&file, &passphrase, &name)?;
            if !entry.username.is_empty() {
                println!("{}", sanitize(&entry.username));
            }
            // The url and realm are informational; print them to stderr so the
            // stdout contract (username, then password under --show) is
            // unchanged.
            if let Some(url) = &entry.url {
                eprintln!("url: {}", sanitize(url));
            }
            if let Some(realm) = &entry.realm {
                eprintln!("realm: {}", sanitize(realm));
            }
            if show {
                println!("{}", entry.password.expose());
            } else {
                pending_clear = Some(copy_to_clipboard(entry.password.expose())?);
                announce_copied(
                    &format!("Password for '{}'", sanitize(&name)),
                    clear_timeout,
                );
            }
        }
        Some(Commands::List { pattern }) => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let entries = mypass::list(&file, &passphrase)?;
            println!("Vault: {} ({} entries)", file.display(), entries.len());
            let pattern = pattern.unwrap_or_default().to_lowercase();
            for entry in entries
                .iter()
                .filter(|e| e.name.to_lowercase().contains(&pattern))
            {
                println!("{}: {}", sanitize(&entry.name), sanitize(&entry.username));
            }
        }
        Some(Commands::Add {
            name,
            username,
            url,
            realm,
            password,
            show,
        }) => {
            let password = obtain_password(&password)?;
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            if show {
                println!("{}", password.expose());
            } else {
                pending_clear = Some(copy_to_clipboard(password.expose())?);
            }
            let entry = PasswordEntry {
                name: name.clone(),
                username: username.unwrap_or_default(),
                password,
                url: normalize_hint(url),
                realm: normalize_hint(realm),
            };
            mypass::add(&file, &passphrase, entry, &params)?;
            if !show {
                announce_copied(
                    &format!("Password for '{}'", sanitize(&name)),
                    clear_timeout,
                );
            }
        }
        Some(Commands::Update {
            name,
            username,
            url,
            realm,
            keep_password,
            password,
            show,
        }) => {
            if keep_password {
                let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
                mypass::update_keep_password(
                    &file,
                    &passphrase,
                    &name,
                    username.unwrap_or_default(),
                    normalize_hint(url),
                    normalize_hint(realm),
                    &params,
                )?;
                println!("Updated entry '{}' (password unchanged).", sanitize(&name));
            } else {
                let password = obtain_password(&password)?;
                let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
                if show {
                    println!("{}", password.expose());
                } else {
                    pending_clear = Some(copy_to_clipboard(password.expose())?);
                }
                let entry = PasswordEntry {
                    name: name.clone(),
                    username: username.unwrap_or_default(),
                    password,
                    url: normalize_hint(url),
                    realm: normalize_hint(realm),
                };
                mypass::update(&file, &passphrase, entry, &params)?;
                if !show {
                    announce_copied(
                        &format!("Password for '{}'", sanitize(&name)),
                        clear_timeout,
                    );
                }
            }
        }
        Some(Commands::Remove { name, yes }) => {
            if !yes && !confirm(&format!("Remove entry '{}'? [y/N] ", sanitize(&name)))? {
                eprintln!("Aborted.");
                return Ok(ExitCode::FAILURE);
            }
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            mypass::remove(&file, &passphrase, &name, &params)?;
            println!("Removed entry '{}'.", sanitize(&name));
        }
        Some(Commands::Generate {
            password_length,
            password_charset,
            show,
        }) => {
            let password = generate(password_length, &password_charset)?;
            if show {
                println!("{}", password.expose());
            } else {
                pending_clear = Some(copy_to_clipboard(password.expose())?);
                announce_copied("Generated password", clear_timeout);
            }
        }
        Some(Commands::Show { name }) => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let entry = mypass::get(&file, &passphrase, &name)?;
            println!("name: {}", sanitize(&entry.name));
            if !entry.username.is_empty() {
                println!("username: {}", sanitize(&entry.username));
            }
            if let Some(url) = &entry.url {
                println!("url: {}", sanitize(url));
            }
            if let Some(realm) = &entry.realm {
                println!("realm: {}", sanitize(realm));
            }
        }
        Some(Commands::Export {}) => {
            let passphrase = obtain_passphrase(cli.passphrase_stdin, false)?;
            let json = mypass::export(&file, &passphrase)?;
            eprintln!("Warning: the decrypted vault follows on stdout.");
            println!("{}", json.as_str());
        }
        Some(Commands::InstallBrowser {
            uninstall,
            snap,
            no_snap,
        }) => {
            install_browser(uninstall, snap, no_snap)?;
        }
        None => {
            if io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal() {
                if cli.passphrase_stdin {
                    bail!("--passphrase-stdin cannot be used with the interactive TUI");
                }
                tui::run(&file, &params, clear_timeout)?;
            } else {
                Cli::command().print_help()?;
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    if let Some(secret) = pending_clear {
        wait_and_clear(&secret, clear_timeout);
    }

    Ok(ExitCode::SUCCESS)
}

/// Read the passphrase, either from stdin (`--passphrase-stdin`) or by
/// prompting on the terminal. `confirm` asks twice (vault creation).
fn obtain_passphrase(from_stdin: bool, confirm: bool) -> anyhow::Result<Passphrase> {
    if from_stdin {
        let mut line = Zeroizing::new(String::new());
        let n = io::stdin()
            .lock()
            .read_line(&mut line)
            .context("cannot read passphrase from stdin")?;
        if n == 0 {
            bail!("no passphrase on stdin");
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(Passphrase::new(std::mem::take(&mut *line)))
    } else {
        let first = Passphrase::new(
            rpassword::prompt_password("Passphrase: ").context("cannot read passphrase")?,
        );
        if confirm {
            let second = Passphrase::new(
                rpassword::prompt_password("Confirm passphrase: ")
                    .context("cannot read passphrase")?,
            );
            if first.as_bytes() != second.as_bytes() {
                bail!("passphrases do not match");
            }
        }
        Ok(first)
    }
}

/// The password for an add/update: typed in, or generated.
fn obtain_password(options: &PasswordOptions) -> anyhow::Result<Secret> {
    if options.input_password {
        Ok(Secret::new(
            rpassword::prompt_password("Password to save: ").context("cannot read password")?,
        ))
    } else {
        generate(options.password_length, &options.password_charset)
    }
}

fn generate(length: u32, charset: &str) -> anyhow::Result<Secret> {
    if length < 8 {
        eprintln!("Warning: {length} characters is a short password.");
    }
    Ok(mypass::generate_password(length, charset)?)
}

/// Write `text` to the system clipboard, returning a zeroizing copy of it so
/// the caller can later clear the clipboard only if it is still unchanged.
fn copy_to_clipboard(text: &str) -> anyhow::Result<Zeroizing<String>> {
    let mut clipboard = Clipboard::get();
    clipboard
        .write_text(text)
        .map_err(|e| anyhow::anyhow!("cannot write to clipboard: {e}"))?;
    Ok(Zeroizing::new(text.to_string()))
}

/// Tell the user a password was copied, mentioning the auto-clear when enabled.
fn announce_copied(what: &str, timeout: u64) {
    if timeout == 0 {
        eprintln!("{what} copied to clipboard.");
    } else if io::stdin().is_terminal() {
        eprintln!("{what} copied to clipboard; clearing in {timeout}s (press ENTER to clear now).");
    } else {
        eprintln!("{what} copied to clipboard; clearing in {timeout}s.");
    }
}

/// Hold the copied password on the clipboard for `timeout` seconds, then clear
/// it. Pressing ENTER during the wait clears immediately; Ctrl-C exits without
/// clearing. The clipboard is only cleared when it still holds our value, so a
/// password the user copied in the meantime is preserved. With `timeout` 0 the
/// clipboard is left untouched.
fn wait_and_clear(secret: &str, timeout: u64) {
    if timeout == 0 {
        return;
    }

    // Pressing ENTER clears immediately. Only watch stdin when it is a
    // terminal, so piped input (e.g. --passphrase-stdin) is left untouched.
    // The reader thread is abandoned when the process exits after the wait.
    let entered = Arc::new(AtomicBool::new(false));
    if io::stdin().is_terminal() {
        let flag = Arc::clone(&entered);
        std::thread::spawn(move || {
            let mut line = String::new();
            if io::stdin().lock().read_line(&mut line).is_ok() {
                flag.store(true, Ordering::SeqCst);
            }
        });
    }

    let deadline = Instant::now() + Duration::from_secs(timeout);
    while Instant::now() < deadline && !entered.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    if clear_if_unchanged(secret) {
        eprintln!("Clipboard cleared.");
    } else {
        eprintln!("Clipboard changed since copy; left as-is.");
    }
}

/// Wipe our password from the clipboard, but only while it still holds that
/// value, so anything the user copied during the wait is left untouched.
/// Returns whether we wiped it.
///
/// We overwrite with a single space rather than emptying the clipboard. The
/// `clip` library behind `clippers` keeps a process-global owner and only
/// hands the clipboard contents to the desktop clipboard manager (e.g.
/// GNOME/mutter) at exit, and *only when its buffer is non-empty*. An empty
/// clear is therefore never propagated: the manager keeps serving the cached
/// password even though this process owned an empty selection. A one-character
/// value makes the hand-off fire and evicts the password.
fn clear_if_unchanged(secret: &str) -> bool {
    let mut clipboard = Clipboard::get();
    let still_ours = clipboard
        .read()
        .and_then(|data| data.into_text())
        .is_some_and(|text| text == secret);
    still_ours && clipboard.write_text(" ").is_ok()
}

fn confirm(prompt: &str) -> anyhow::Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Treat an absent or empty `--url`/`--realm` as "not set", so an entry
/// without one stays byte-identical to the format before that field existed
/// rather than carrying an empty string.
fn normalize_hint(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
}

/// Replace control, bidirectional and zero-width characters before echoing
/// vault content to a terminal, in case a vault contains names this version
/// would not accept (an old, imported or shared vault). This blocks
/// Trojan-Source / homoglyph style display spoofing.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || mypass::is_display_spoofing_char(c) {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}
