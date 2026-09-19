//! Opt-in debug logging to a file, for diagnosing the native-messaging
//! integration when it cannot be run from a terminal (the host's stderr goes
//! nowhere under Firefox). Disabled unless a log path is configured, either by
//! `log_file` in `~/.config/mypass/browser.json` or the `$MYPASS_BROWSER_LOG`
//! environment variable.
//!
//! It must never record secrets: callers log protocol structure only, and the
//! pinentry passphrase data line is redacted to its length. Lines are appended
//! with an `open`/`write`/`close` per call so a crash cannot lose buffered
//! output and no file handle lingers holding the log open.

use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static LOG_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Record the log destination once at startup. `None` (or a never-`init`ed
/// logger) disables logging entirely.
pub fn init(path: Option<PathBuf>) {
    let _ = LOG_PATH.set(path);
}

/// Whether logging is active, so callers can skip building messages otherwise.
pub fn enabled() -> bool {
    matches!(LOG_PATH.get(), Some(Some(_)))
}

/// Append one timestamped line. Best-effort: a logging failure is ignored so it
/// can never affect the integration's behaviour.
pub fn log(message: &str) {
    let Some(Some(path)) = LOG_PATH.get() else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{} pid={} {message}", timestamp(), std::process::id());
    }
}

/// Seconds.milliseconds since the Unix epoch — enough to correlate events
/// without pulling in a date-formatting dependency.
fn timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => format!("{}.{:03}", d.as_secs(), d.subsec_millis()),
        Err(_) => "0.000".to_string(),
    }
}
