//! A minimal Assuan client for `pinentry`. Only the
//! subset the host needs is implemented: `SETTITLE`/`SETDESC`/`SETPROMPT`/
//! `SETERROR`/`GETPIN` to read the master passphrase. The passphrase is
//! returned in a zeroizing buffer and never crosses any other process
//! boundary.
//!
//! A fresh `pinentry` is spawned per prompt so each call is self-contained and
//! no dialog state leaks between attempts.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use zeroize::Zeroizing;

/// The `pinentry` program, overridable via `$MYPASS_PINENTRY` (used by tests and
/// for unusual installs).
fn pinentry_program() -> OsString {
    std::env::var_os("MYPASS_PINENTRY")
        .or_else(|| std::env::var_os("PW_PINENTRY"))
        .unwrap_or_else(|| "pinentry".into())
}

#[derive(Debug)]
pub enum Error {
    /// The user dismissed the dialog (Cancel / Escape).
    Cancelled,
    /// `pinentry` could not be started or spoke unexpectedly.
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Cancelled => f.write_str("pinentry cancelled by user"),
            Error::Failed(m) => write!(f, "pinentry failed: {m}"),
        }
    }
}

/// Prompt for the master passphrase. `error` populates pinentry's error line
/// on a retry (e.g. after a wrong passphrase).
pub fn get_passphrase(
    desc: &str,
    prompt: &str,
    error: Option<&str>,
) -> Result<Zeroizing<String>, Error> {
    let mut pe = Pinentry::spawn()?;
    pe.forward_environment();
    pe.send("SETTITLE MyPass")?;
    pe.send(&format!("SETDESC {}", encode(desc)))?;
    pe.send(&format!("SETPROMPT {}", encode(prompt)))?;
    if let Some(error) = error {
        pe.send(&format!("SETERROR {}", encode(error)))?;
    }
    pe.getpin()
}

struct Pinentry {
    child: Child,
    reader: BufReader<ChildStdout>,
    writer: ChildStdin,
}

impl Pinentry {
    fn spawn() -> Result<Pinentry, Error> {
        crate::debug_log::log(&format!("pinentry: spawning {:?}", pinentry_program()));
        let mut child = Command::new(pinentry_program())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Failed(format!("cannot start pinentry: {e}")))?;
        let reader = BufReader::new(child.stdout.take().expect("piped stdout"));
        let writer = child.stdin.take().expect("piped stdin");
        let mut pe = Pinentry {
            child,
            reader,
            writer,
        };
        // The server greets with `OK` before accepting commands.
        match pe.read_line()? {
            Line::Ok => Ok(pe),
            other => Err(Error::Failed(format!("unexpected greeting: {other:?}"))),
        }
    }

    /// Tell pinentry where the user's display, terminal and locale are — the
    /// same `OPTION` commands `gpg-agent` sends before every prompt. Without
    /// them a pinentry started outside a terminal (as this host always is,
    /// especially when launched by the Firefox/snap native-messaging portal
    /// with a stripped-down environment) may put up a dialog it cannot
    /// complete, leaving the host blocked on `GETPIN` forever.
    ///
    /// Every option is best-effort: only variables that are actually set are
    /// forwarded, and a pinentry that rejects one (`ERR`) must not abort the
    /// prompt. `ttyname` is sent only when a terminal is known (`GPG_TTY`), so
    /// the GUI path is preferred when there is none.
    fn forward_environment(&mut self) {
        let mut opt = |name: &str, var: &str| {
            if let Some(value) = std::env::var_os(var) {
                if let Some(value) = value.to_str() {
                    if !value.is_empty() {
                        let _ = self.send_option(&format!("OPTION {name}={}", encode(value)));
                    }
                }
            }
        };
        opt("display", "DISPLAY");
        opt("ttyname", "GPG_TTY");
        opt("ttytype", "TERM");
        // Locale for the dialog text; LC_* win over LANG, matching gpg-agent.
        for var in ["LC_CTYPE", "LC_ALL", "LANG"] {
            if std::env::var_os(var).is_some() {
                opt("lc-ctype", var);
                break;
            }
        }
        for var in ["LC_MESSAGES", "LC_ALL", "LANG"] {
            if std::env::var_os(var).is_some() {
                opt("lc-messages", var);
                break;
            }
        }
    }

    /// Send an `OPTION` command, tolerating an `ERR` reply: an option the
    /// installed pinentry does not understand is harmless and must not fail
    /// the prompt (unlike the `SET*` commands handled by [`send`]).
    fn send_option(&mut self, command: &str) -> Result<(), Error> {
        crate::debug_log::log(&format!("pinentry -> {command}"));
        writeln!(self.writer, "{command}")
            .and_then(|()| self.writer.flush())
            .map_err(|e| Error::Failed(format!("write to pinentry: {e}")))?;
        match self.read_line()? {
            Line::Ok | Line::Err(_) => Ok(()),
            other => Err(Error::Failed(format!("unexpected reply: {other:?}"))),
        }
    }

    /// Send a command and require an `OK` reply (used for the `SET*` commands).
    fn send(&mut self, command: &str) -> Result<(), Error> {
        crate::debug_log::log(&format!("pinentry -> {command}"));
        writeln!(self.writer, "{command}")
            .and_then(|()| self.writer.flush())
            .map_err(|e| Error::Failed(format!("write to pinentry: {e}")))?;
        match self.read_line()? {
            Line::Ok => Ok(()),
            Line::Err(msg) => Err(Error::Failed(msg)),
            other => Err(Error::Failed(format!("unexpected reply: {other:?}"))),
        }
    }

    fn getpin(&mut self) -> Result<Zeroizing<String>, Error> {
        crate::debug_log::log("pinentry -> GETPIN");
        writeln!(self.writer, "GETPIN")
            .and_then(|()| self.writer.flush())
            .map_err(|e| Error::Failed(format!("write to pinentry: {e}")))?;
        let mut pin: Option<Zeroizing<String>> = None;
        loop {
            match self.read_line()? {
                Line::Data(bytes) => {
                    pin = Some(Zeroizing::new(
                        String::from_utf8(bytes.to_vec())
                            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
                    ));
                }
                Line::Ok => return Ok(pin.unwrap_or_else(|| Zeroizing::new(String::new()))),
                // Any error from GETPIN (cancel, timeout) means no passphrase.
                Line::Err(_) => return Err(Error::Cancelled),
                Line::Other => {}
            }
        }
    }

    fn read_line(&mut self) -> Result<Line, Error> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| Error::Failed(format!("read from pinentry: {e}")))?;
        if n == 0 {
            return Err(Error::Failed("pinentry closed the connection".to_string()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let parsed = if let Some(rest) = trimmed.strip_prefix("D ") {
            Line::Data(Zeroizing::new(decode(rest)))
        } else if trimmed == "OK" || trimmed.starts_with("OK ") {
            Line::Ok
        } else if let Some(rest) = trimmed.strip_prefix("ERR ") {
            Line::Err(rest.to_string())
        } else {
            // S (status), # (comment), INQUIRE, etc. — ignored.
            Line::Other
        };
        if crate::debug_log::enabled() {
            // Never log the passphrase: the `D` data line is reduced to its
            // length. Every other line is protocol chatter and safe to record.
            match &parsed {
                Line::Data(bytes) => {
                    crate::debug_log::log(&format!("pinentry <- D <redacted len={}>", bytes.len()))
                }
                Line::Ok => crate::debug_log::log("pinentry <- OK"),
                Line::Err(msg) => crate::debug_log::log(&format!("pinentry <- ERR {msg}")),
                Line::Other => crate::debug_log::log(&format!("pinentry <- {trimmed}")),
            }
        }
        // The raw line may have held the percent-encoded passphrase.
        line.zeroize_in_place();
        Ok(parsed)
    }
}

impl Drop for Pinentry {
    fn drop(&mut self) {
        // Shut pinentry down and reap it so it does not linger — but never
        // block the host indefinitely doing so. Once `GETPIN` has returned the
        // passphrase, a misbehaving pinentry must not be allowed to hang the
        // whole host on `wait()`; in particular `pinentry-gnome3` can wedge in
        // a GUI/D-Bus call and sit in uninterruptible sleep where even
        // `SIGKILL` is deferred.
        //
        // First ask it to quit cleanly with the Assuan `BYE` command: a clean
        // exit closes the gcr prompt properly, which `SIGKILL` mid-dialog can
        // otherwise leave stuck. If it has not gone after a short grace period,
        // force it, then poll again — and ultimately give up reaping rather
        // than wait forever (the OS reclaims the child when the host exits).
        let _ = writeln!(self.writer, "BYE");
        let _ = self.writer.flush();
        if self.reap_within(10) {
            return; // exited cleanly on BYE
        }
        let _ = self.child.kill();
        if self.reap_within(30) {
            return;
        }
        crate::debug_log::log("pinentry: did not exit after kill; abandoning reap");
    }
}

impl Pinentry {
    /// Poll for the child to exit, up to `cycles` × 50 ms. Returns whether it
    /// was reaped (or had already gone); never blocks longer than the budget.
    fn reap_within(&mut self, cycles: u32) -> bool {
        for _ in 0..cycles {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return true,
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        false
    }
}

#[derive(Debug)]
enum Line {
    Data(Zeroizing<Vec<u8>>),
    Ok,
    Err(String),
    Other,
}

/// Percent-encode a value for an Assuan command line: `%` and control
/// characters must be escaped; everything else (including spaces) passes
/// through.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '%' || c.is_control() {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Decode percent-escapes in an Assuan data line back to raw bytes.
fn decode(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Best-effort scrub of a `String`'s bytes in place.
trait ZeroizeInPlace {
    fn zeroize_in_place(&mut self);
}

impl ZeroizeInPlace for String {
    fn zeroize_in_place(&mut self) {
        use zeroize::Zeroize;
        // SAFETY: zeroing bytes leaves the String empty-able; we clear after.
        unsafe {
            self.as_mut_vec().zeroize();
        }
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn encode_escapes_percent_and_controls() {
        assert_eq!(encode("Unlock ~/mypass.scrypt"), "Unlock ~/mypass.scrypt");
        assert_eq!(encode("100%"), "100%25");
        assert_eq!(encode("a\nb"), "a%0Ab");
    }

    #[test]
    fn decode_reverses_encoding() {
        assert_eq!(decode("a%0Ab"), b"a\nb");
        assert_eq!(decode("100%25"), b"100%");
        assert_eq!(decode("plain"), b"plain");
        // A stray percent with no hex digits is passed through literally.
        assert_eq!(decode("50%"), b"50%");
    }
}
