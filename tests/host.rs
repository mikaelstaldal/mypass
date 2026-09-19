//! Wire-protocol tests for `mypass-browser-host`. These
//! exercise the framing, request dispatch and error paths that do not need a
//! `pinentry` dialog or a real vault: `status`, `lock`, an ineligible origin,
//! a request with no origin, and an unknown request type.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// The package version is reported in `status.version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Locate the `mypass-browser-host` binary next to this test executable. The test
/// is built into `<target>/debug/deps/`; the binary targets live one level up.
fn host_bin() -> PathBuf {
    let mut path = std::env::current_exe().expect("current exe");
    path.pop(); // drop the test executable
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("mypass-browser-host");
    path
}

struct Host {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl Host {
    fn spawn() -> Host {
        // Point the host at a config path that does not exist so it uses
        // built-in defaults and never reads a developer's real vault.
        let mut child = Command::new(host_bin())
            .env(
                "MYPASS_BROWSER_CONFIG",
                "/nonexistent/mypass-browser-host-test.json",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mypass-browser-host");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Host {
            child,
            stdin,
            stdout,
        }
    }

    fn request(&mut self, json: &str) -> String {
        let bytes = json.as_bytes();
        self.stdin
            .write_all(&(bytes.len() as u32).to_ne_bytes())
            .unwrap();
        self.stdin.write_all(bytes).unwrap();
        self.stdin.flush().unwrap();

        let mut len = [0u8; 4];
        self.stdout.read_exact(&mut len).unwrap();
        let n = u32::from_ne_bytes(len) as usize;
        let mut buf = vec![0u8; n];
        self.stdout.read_exact(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn finish(mut self) {
        drop(self.stdin); // EOF -> the host exits its read loop
        let status = self.child.wait().unwrap();
        assert!(status.success(), "host exited with {status:?}");
    }
}

#[test]
fn status_reports_locked_and_version() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":1,"type":"status"}"#);
    assert!(resp.contains(r#""type":"status""#), "{resp}");
    assert!(resp.contains(r#""id":1"#), "{resp}");
    assert!(resp.contains(r#""locked":true"#), "{resp}");
    assert!(
        resp.contains(&format!(r#""version":"{VERSION}""#)),
        "{resp}"
    );
    host.finish();
}

#[test]
fn lock_is_acknowledged() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":2,"type":"lock"}"#);
    assert!(resp.contains(r#""type":"ok""#), "{resp}");
    assert!(resp.contains(r#""id":2"#), "{resp}");
    host.finish();
}

#[test]
fn non_https_origin_is_rejected_without_unlocking() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":3,"type":"get-logins","origin":"http://example.com"}"#);
    assert!(resp.contains(r#""type":"error""#), "{resp}");
    assert!(resp.contains(r#""code":"invalid-origin""#), "{resp}");
    assert!(resp.contains(r#""id":3"#), "{resp}");
    host.finish();
}

#[test]
fn missing_origin_is_rejected() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":4,"type":"get-logins"}"#);
    assert!(resp.contains(r#""code":"invalid-origin""#), "{resp}");
    host.finish();
}

#[test]
fn unknown_request_type_is_an_internal_error() {
    let mut host = Host::spawn();
    let resp = host.request(r#"{"id":5,"type":"frobnicate"}"#);
    assert!(resp.contains(r#""type":"error""#), "{resp}");
    assert!(resp.contains(r#""code":"internal""#), "{resp}");
    assert!(resp.contains(r#""id":5"#), "{resp}");
    host.finish();
}

#[test]
fn several_requests_on_one_connection() {
    let mut host = Host::spawn();
    assert!(host
        .request(r#"{"id":1,"type":"status"}"#)
        .contains(r#""type":"status""#));
    assert!(host
        .request(r#"{"id":2,"type":"lock"}"#)
        .contains(r#""type":"ok""#));
    assert!(host
        .request(r#"{"id":3,"type":"status"}"#)
        .contains(r#""locked":true"#));
    host.finish();
}

/// A temporary vault, host config and stub pinentry: everything the paths that
/// really unlock need. Nothing here touches the developer's own vault — the
/// config always names a file inside the temporary directory, so a host that
/// unexpectedly tries to unlock cannot end up prompting for a real passphrase.
#[cfg(unix)]
struct Fixture {
    _dir: tempfile::TempDir,
    config: PathBuf,
    stub: PathBuf,
    cmdlog: PathBuf,
}

#[cfg(unix)]
impl Fixture {
    /// A fixture whose vault holds an untagged entry for `example.com` and
    /// two realm-scoped ones for `multi.example`.
    fn new(cache_minutes: u64) -> Fixture {
        Fixture::build(cache_minutes, true)
    }

    /// A fixture whose config points at a vault that does not exist.
    fn without_vault() -> Fixture {
        Fixture::build(10, false)
    }

    fn build(cache_minutes: u64, create_vault: bool) -> Fixture {
        use mypass::{add, init, Params, Passphrase, PasswordEntry};
        use std::os::unix::fs::PermissionsExt;

        // Small KDF parameters keep the unlock fast in debug builds.
        const PARAMS: Params = Params {
            log_n: 12,
            r: 8,
            p: 1,
        };

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.scrypt");
        if create_vault {
            let passphrase = Passphrase::new("test passphrase".to_string());
            init(&vault, &passphrase, &PARAMS).unwrap();
            // One untagged entry, plus two realms under a second host: enough
            // to exercise both the wildcard and the realm-scoped match.
            for (name, username, password, url, realm) in [
                ("example.com", "alice", "s3cret", "example.com", None),
                (
                    "multi-admin",
                    "adm",
                    "adm-pw",
                    "multi.example",
                    Some("Admin"),
                ),
                ("multi-wiki", "wik", "wik-pw", "multi.example", Some("Wiki")),
            ] {
                add(
                    &vault,
                    &passphrase,
                    PasswordEntry {
                        name: name.to_string(),
                        username: username.to_string(),
                        password: password.into(),
                        url: Some(url.to_string()),
                        realm: realm.map(str::to_string),
                    },
                    &PARAMS,
                )
                .unwrap();
            }
        }

        let config = dir.path().join("browser.json");
        std::fs::write(
            &config,
            format!(
                r#"{{"file":{:?},"cache_minutes":{cache_minutes}}}"#,
                vault.to_str().unwrap()
            ),
        )
        .unwrap();

        // A stub pinentry: it logs every command it is sent and answers GETPIN
        // with the test passphrase. The data line uses Assuan percent-encoding
        // (`%20` for the space) just as a real pinentry would.
        let cmdlog = dir.path().join("pinentry-cmds.log");
        let stub = dir.path().join("stub-pinentry");
        std::fs::write(
            &stub,
            "#!/bin/sh\n\
             printf 'OK ready\\n'\n\
             while IFS= read -r line; do\n\
               printf '%s\\n' \"$line\" >> \"$PW_TEST_CMDLOG\"\n\
               case \"$line\" in\n\
                 GETPIN) printf 'D test%%20passphrase\\n'; printf 'OK\\n' ;;\n\
                 BYE) printf 'OK\\n'; exit 0 ;;\n\
                 *) printf 'OK\\n' ;;\n\
               esac\n\
             done\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        Fixture {
            _dir: dir,
            config,
            stub,
            cmdlog,
        }
    }

    /// Everything the stub pinentry was sent, in order.
    fn pinentry_commands(&self) -> String {
        std::fs::read_to_string(&self.cmdlog).unwrap_or_default()
    }
}

#[cfg(unix)]
impl Host {
    /// Spawn a host against `fixture`, with the environment a pinentry needs
    /// to locate the session.
    fn spawn_with_pinentry(fixture: &Fixture) -> Host {
        let mut child = Command::new(host_bin())
            .env("MYPASS_BROWSER_CONFIG", &fixture.config)
            .env("MYPASS_PINENTRY", &fixture.stub)
            .env("PW_TEST_CMDLOG", &fixture.cmdlog)
            .env("DISPLAY", ":0")
            .env("TERM", "xterm-256color")
            .env("LANG", "en_US.UTF-8")
            .env_remove("GPG_TTY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mypass-browser-host");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        Host {
            child,
            stdin,
            stdout,
        }
    }
}

/// A `get-logins` that has to unlock must first tell pinentry where the user's
/// display/terminal and locale are (the `OPTION` commands `gpg-agent` sends),
/// or a pinentry launched outside a terminal — as it always is here — can put
/// up a dialog it never completes, hanging the host on `GETPIN`. This drives
/// the full unlock path against a stub pinentry that records what it received.
#[cfg(unix)]
#[test]
fn get_logins_forwards_environment_to_pinentry() {
    // `cache_minutes:0` so the unlock is exercised on every request.
    let fixture = Fixture::new(0);
    let mut host = Host::spawn_with_pinentry(&fixture);
    let resp = host.request(r#"{"id":7,"type":"get-logins","origin":"https://example.com"}"#);
    host.finish();

    // The unlock succeeded and the entry was released.
    assert!(resp.contains(r#""type":"logins""#), "{resp}");
    assert!(resp.contains(r#""name":"example.com""#), "{resp}");

    // pinentry was told the environment, before any SET* command.
    let cmds = fixture.pinentry_commands();
    assert!(cmds.contains("OPTION display=:0"), "{cmds}");
    assert!(cmds.contains("OPTION ttytype=xterm-256color"), "{cmds}");
    assert!(cmds.contains("OPTION lc-ctype=en_US.UTF-8"), "{cmds}");
    assert!(cmds.contains("OPTION lc-messages=en_US.UTF-8"), "{cmds}");
    // No terminal was advertised (GPG_TTY unset), so the GUI path is kept.
    assert!(!cmds.contains("OPTION ttyname"), "{cmds}");
    let display_at = cmds.find("OPTION display").unwrap();
    let settitle_at = cmds.find("SETTITLE").unwrap();
    assert!(
        display_at < settitle_at,
        "options must precede SET*: {cmds}"
    );
}

/// `unlock` is the point of the toolbar's unlock button: one passphrase entry,
/// after which fills happen without prompting until the cache expires. It must
/// unlock without releasing anything, and the following `get-logins` must not
/// prompt again.
#[cfg(unix)]
#[test]
fn unlock_prompts_once_and_releases_nothing() {
    let fixture = Fixture::new(10);
    let mut host = Host::spawn_with_pinentry(&fixture);

    let resp = host.request(r#"{"id":1,"type":"unlock"}"#);
    assert!(resp.contains(r#""type":"status""#), "{resp}");
    assert!(resp.contains(r#""id":1"#), "{resp}");
    assert!(resp.contains(r#""locked":false"#), "{resp}");
    // No entry, username or password rides along on an unlock.
    assert!(!resp.contains("alice"), "{resp}");
    assert!(!resp.contains("s3cret"), "{resp}");
    assert!(!resp.contains("example.com"), "{resp}");

    let resp = host.request(r#"{"id":2,"type":"get-logins","origin":"https://example.com"}"#);
    assert!(resp.contains(r#""type":"logins""#), "{resp}");
    assert!(resp.contains(r#""name":"example.com""#), "{resp}");
    host.finish();

    // One unlock, one passphrase prompt.
    let prompts = fixture.pinentry_commands().matches("GETPIN").count();
    assert_eq!(prompts, 1, "{}", fixture.pinentry_commands());
}

/// With `cache_minutes: 0` the host drops the entries as soon as it answers,
/// so an unlock cannot outlive the response — and must say so rather than
/// leaving the toolbar claiming the vault is unlocked.
#[cfg(unix)]
#[test]
fn unlock_reports_locked_when_caching_is_disabled() {
    let fixture = Fixture::new(0);
    let mut host = Host::spawn_with_pinentry(&fixture);
    let resp = host.request(r#"{"id":1,"type":"unlock"}"#);
    assert!(resp.contains(r#""type":"status""#), "{resp}");
    assert!(resp.contains(r#""locked":true"#), "{resp}");
    host.finish();
}

/// The gesture-less HTTP-auth path matches the host exactly. A parent-domain
/// match is right for a fill the user clicks for, but here it would let a
/// subdomain someone else controls — a dangling CNAME, shared hosting, one
/// tenant of a multi-tenant apex — collect the parent domain's password with
/// no dialog to notice.
#[cfg(unix)]
#[test]
fn strict_get_logins_matches_the_host_exactly() {
    let fixture = Fixture::new(10);
    let mut host = Host::spawn_with_pinentry(&fixture);
    assert!(host
        .request(r#"{"id":1,"type":"unlock"}"#)
        .contains(r#""locked":false"#));

    let resp =
        host.request(r#"{"id":2,"type":"get-logins-strict","origin":"https://example.com"}"#);
    assert!(resp.contains(r#""type":"logins""#), "{resp}");
    assert!(resp.contains(r#""name":"example.com""#), "{resp}");

    let resp =
        host.request(r#"{"id":3,"type":"get-logins-strict","origin":"https://evil.example.com"}"#);
    assert!(resp.contains(r#""code":"no-match""#), "{resp}");
    assert!(!resp.contains("s3cret"), "{resp}");

    // The same host, asked the gesture-driven way, still matches the parent
    // domain — the two rules are deliberately different.
    let resp = host.request(r#"{"id":4,"type":"get-logins","origin":"https://evil.example.com"}"#);
    assert!(resp.contains(r#""type":"logins""#), "{resp}");
    host.finish();
}

/// A strict request answers a locked vault instead of prompting. The browser
/// sends it with no user gesture behind it, so a pinentry dialog here would be
/// one that a visited page caused.
#[cfg(unix)]
#[test]
fn strict_get_logins_declines_instead_of_prompting() {
    let fixture = Fixture::new(10);
    let mut host = Host::spawn_with_pinentry(&fixture);
    let resp =
        host.request(r#"{"id":1,"type":"get-logins-strict","origin":"https://example.com"}"#);
    assert!(resp.contains(r#""type":"error""#), "{resp}");
    assert!(resp.contains(r#""code":"locked""#), "{resp}");
    host.finish();
    assert_eq!(fixture.pinentry_commands(), "", "must not prompt");
}

/// A failed unlock reports the same error codes as a fill, and never prompts
/// when there is no vault to open.
#[cfg(unix)]
#[test]
fn unlock_without_a_vault_reports_db_missing() {
    let fixture = Fixture::without_vault();
    let mut host = Host::spawn_with_pinentry(&fixture);
    let resp = host.request(r#"{"id":9,"type":"unlock"}"#);
    assert!(resp.contains(r#""type":"error""#), "{resp}");
    assert!(resp.contains(r#""code":"db-missing""#), "{resp}");
    assert!(resp.contains(r#""id":9"#), "{resp}");
    host.finish();
    assert_eq!(fixture.pinentry_commands(), "", "must not prompt");
}

/// `get-logins-strict-unlock` is the escape hatch for the gesture-less path:
/// the extension sends it only from the click on its own unlock button, so it
/// may prompt. It must still match the host exactly, and it must do the
/// unlocking and the matching in one request — with `cache_minutes: 0`, which
/// is what this fixture uses, a separate `unlock` would have expired before a
/// following `get-logins-strict` could use it.
#[cfg(unix)]
#[test]
fn strict_unlock_get_logins_prompts_and_still_matches_exactly() {
    let fixture = Fixture::new(0);
    let mut host = Host::spawn_with_pinentry(&fixture);

    let resp = host
        .request(r#"{"id":1,"type":"get-logins-strict-unlock","origin":"https://example.com"}"#);
    assert!(resp.contains(r#""type":"logins""#), "{resp}");
    assert!(resp.contains(r#""name":"example.com""#), "{resp}");
    assert_eq!(
        fixture.pinentry_commands().matches("GETPIN").count(),
        1,
        "{}",
        fixture.pinentry_commands()
    );

    // Unlocking does not loosen the matching: a subdomain is still not a match.
    let resp = host.request(
        r#"{"id":2,"type":"get-logins-strict-unlock","origin":"https://evil.example.com"}"#,
    );
    assert!(resp.contains(r#""code":"no-match""#), "{resp}");
    assert!(!resp.contains("s3cret"), "{resp}");
    host.finish();
}

/// An ineligible origin is refused before anything is decrypted, on the
/// unlocking variant too — a plain `http:` page must not be able to reach
/// pinentry through it.
#[cfg(unix)]
#[test]
fn strict_unlock_get_logins_rejects_an_ineligible_origin_without_prompting() {
    let fixture = Fixture::new(10);
    let mut host = Host::spawn_with_pinentry(&fixture);
    let resp =
        host.request(r#"{"id":1,"type":"get-logins-strict-unlock","origin":"http://example.com"}"#);
    assert!(resp.contains(r#""code":"invalid-origin""#), "{resp}");
    host.finish();
    assert_eq!(fixture.pinentry_commands(), "", "must not prompt");
}

/// The realm completes the protection space: with it, a host running several
/// realms releases exactly the entry for the one being challenged, and the
/// extension's chooser never has to appear.
#[cfg(unix)]
#[test]
fn strict_get_logins_selects_by_realm() {
    let fixture = Fixture::new(10);
    let mut host = Host::spawn_with_pinentry(&fixture);
    assert!(host
        .request(r#"{"id":1,"type":"unlock"}"#)
        .contains(r#""locked":false"#));

    let resp = host.request(
        r#"{"id":2,"type":"get-logins-strict","origin":"https://multi.example","realm":"Admin"}"#,
    );
    assert!(resp.contains(r#""name":"multi-admin""#), "{resp}");
    assert!(!resp.contains("multi-wiki"), "{resp}");
    assert!(!resp.contains("wik-pw"), "{resp}");

    let resp = host.request(
        r#"{"id":3,"type":"get-logins-strict","origin":"https://multi.example","realm":"Wiki"}"#,
    );
    assert!(resp.contains(r#""name":"multi-wiki""#), "{resp}");
    assert!(!resp.contains("adm-pw"), "{resp}");

    // A realm no entry names, and a challenge carrying none at all, release
    // nothing here: both realmed entries say they belong elsewhere.
    for request in [
        r#"{"id":4,"type":"get-logins-strict","origin":"https://multi.example","realm":"Other"}"#,
        r#"{"id":5,"type":"get-logins-strict","origin":"https://multi.example"}"#,
    ] {
        let resp = host.request(request);
        assert!(resp.contains(r#""code":"no-match""#), "{resp}");
        assert!(!resp.contains("adm-pw"), "{resp}");
        assert!(!resp.contains("wik-pw"), "{resp}");
    }
    host.finish();
}

/// An entry with no realm is a wildcard over its host — which is what every
/// entry written before the field existed is, so an old vault keeps answering
/// whatever realm a site challenges for.
#[cfg(unix)]
#[test]
fn an_unrealmed_entry_answers_any_realm() {
    let fixture = Fixture::new(10);
    let mut host = Host::spawn_with_pinentry(&fixture);
    assert!(host
        .request(r#"{"id":1,"type":"unlock"}"#)
        .contains(r#""locked":false"#));

    for request in [
        r#"{"id":2,"type":"get-logins-strict","origin":"https://example.com","realm":"Anything"}"#,
        r#"{"id":3,"type":"get-logins-strict","origin":"https://example.com"}"#,
    ] {
        let resp = host.request(request);
        assert!(resp.contains(r#""name":"example.com""#), "{resp}");
    }
    host.finish();
}

/// The realm is HTTP-authentication metadata; a login form belongs to no
/// protection space, so the gesture-driven path ignores it rather than hiding
/// entries the user clicked to fill.
#[cfg(unix)]
#[test]
fn the_gesture_driven_match_ignores_the_realm() {
    let fixture = Fixture::new(10);
    let mut host = Host::spawn_with_pinentry(&fixture);
    assert!(host
        .request(r#"{"id":1,"type":"unlock"}"#)
        .contains(r#""locked":false"#));
    let resp = host.request(
        r#"{"id":2,"type":"get-logins","origin":"https://multi.example","realm":"Other"}"#,
    );
    assert!(resp.contains(r#""name":"multi-admin""#), "{resp}");
    assert!(resp.contains(r#""name":"multi-wiki""#), "{resp}");
    host.finish();
}
