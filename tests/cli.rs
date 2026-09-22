use std::path::{Path, PathBuf};

use assert_cmd::Command;
use assert_fs::TempDir;
use mypass::{scrypt_format, Params};
use predicates::prelude::*;
use predicates::str::contains;

const PASSPHRASE: &str = "test passphrase\n";

/// A `pw` command against `vault`, with the passphrase taken from stdin and
/// small scrypt parameters so debug-mode tests stay fast.
fn pw(vault: &Path) -> Command {
    let mut cmd = Command::cargo_bin("mypass").unwrap();
    cmd.arg("--file")
        .arg(vault)
        .args(["--passphrase-stdin", "--scrypt-log-n", "12"]);
    cmd
}

fn init_vault(dir: &TempDir) -> PathBuf {
    let vault = dir.path().join("pw.scrypt");
    pw(&vault)
        .arg("init")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("Initialized empty vault"));
    vault
}

/// Add an entry with a generated password and return that password.
fn add_entry(vault: &Path, name: &str, username: &str) -> String {
    let assert = pw(vault)
        .args(["add", name, username, "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    stdout.trim_end().to_string()
}

fn write_raw_vault(vault: &Path, json: &str) {
    let ciphertext = scrypt_format::encrypt(
        json.as_bytes(),
        b"test passphrase",
        &Params {
            log_n: 12,
            r: 8,
            p: 1,
        },
    )
    .unwrap();
    std::fs::write(vault, ciphertext).unwrap();
}

#[test]
fn repair_removes_malformed_and_chooses_duplicate() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    write_raw_vault(
        &vault,
        r#"{"version":1,"created":"2020","entries":[{"name":"bad","username":"u","password":8675309},{"name":"same","username":"old","password":"one"},{"name":"same","username":"new","password":"two","note":"keep me"}]}"#,
    );
    let before = std::fs::read(&vault).unwrap();
    pw(&vault)
        .arg("repair")
        .write_stdin(format!("{PASSPHRASE}y\n2\n"))
        .assert()
        .success()
        .stdout(contains("Removed 2 entries"))
        .stderr(
            contains("malformed")
                .and(contains("Duplicate entry name 'same'"))
                .and(contains("passwords different"))
                .and(predicates::str::is_match("8675309").unwrap().not()),
        );
    pw(&vault)
        .args(["get", "same", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout("new\ntwo\n");
    assert_eq!(
        std::fs::read(mypass::vault::backup_path(&vault)).unwrap(),
        before
    );
    let plain =
        scrypt_format::decrypt(&std::fs::read(&vault).unwrap(), b"test passphrase").unwrap();
    let repaired: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(repaired["created"], "2020");
    assert_eq!(repaired["entries"][0]["note"], "keep me");
}

#[test]
fn repair_reports_same_password_for_distinct_entries() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    write_raw_vault(
        &vault,
        r#"{"version":1,"entries":[{"name":"same","username":"a","password":"secret"},{"name":"same","username":"b","password":"secret"}]}"#,
    );
    // The second newline is the empty answer that leaves both copies in place.
    pw(&vault)
        .arg("repair")
        .write_stdin(format!("{PASSPHRASE}\n"))
        .assert()
        .success()
        .stderr(contains("passwords same").and(contains("secret").not()));
}

#[test]
fn repair_legacy_array_keeps_array_and_no_change_does_not_write() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    write_raw_vault(
        &vault,
        r#"[{"name":"same","username":"a","password":"one"},{"name":"same","username":"b","password":"two"}]"#,
    );
    let before = std::fs::read(&vault).unwrap();
    pw(&vault)
        .arg("repair")
        .write_stdin(format!("{PASSPHRASE}\n"))
        .assert()
        .success()
        .stdout(contains("No changes made"));
    assert_eq!(std::fs::read(&vault).unwrap(), before);
    pw(&vault)
        .arg("repair")
        .write_stdin(format!("{PASSPHRASE}1\n"))
        .assert()
        .success();
    let plain =
        scrypt_format::decrypt(&std::fs::read(&vault).unwrap(), b"test passphrase").unwrap();
    let repaired: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert!(repaired.is_array());
    assert_eq!(repaired.as_array().unwrap().len(), 1);
}

#[test]
fn repair_reports_malformed_envelope_without_fabricated_eof() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    write_raw_vault(&vault, r#"{"version":1,"entrys":[]}"#);
    pw(&vault)
        .arg("repair")
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("entries must be an array").and(contains("EOF while parsing").not()));
}

#[test]
fn repair_eof_leaves_vault_unchanged() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    write_raw_vault(
        &vault,
        r#"{"version":1,"entries":[{"name":"bad","username":"u","password":42}]}"#,
    );
    let before = std::fs::read(&vault).unwrap();
    pw(&vault)
        .arg("repair")
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("vault unchanged"));
    assert_eq!(std::fs::read(&vault).unwrap(), before);
}

#[test]
fn init_creates_vault() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    assert!(vault.exists());
}

#[test]
fn init_fails_if_vault_already_exists() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .arg("init")
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn get_fails_if_vault_does_not_exist() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    pw(&vault)
        .args(["get", "bogus"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("run `mypass init`"));
}

#[test]
fn tui_rejects_passphrase_stdin() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .arg("tui")
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains(
            "--passphrase-stdin cannot be used with the interactive TUI",
        ));
}

#[test]
fn add_then_get_round_trip() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let password = add_entry(&vault, "foo", "user1");
    assert_eq!(password.chars().count(), 16);

    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(format!("user1\n{password}\n"));
}

#[test]
fn add_without_username() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let password = add_entry(&vault, "foo", "");

    // No username line, just the password.
    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(format!("{password}\n"));
}

#[test]
fn get_unknown_entry() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["get", "bogus", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("no entry 'bogus'").and(contains("try `mypass list`")));
}

#[test]
fn add_duplicate_entry() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");
    pw(&vault)
        .args(["add", "foo", "user2", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("already exists").and(contains("use `mypass update`")));
}

#[test]
fn update_changes_the_password() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    let assert = pw(&vault)
        .args(["update", "foo", "user2", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    let new_password = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim_end()
        .to_string();

    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(format!("user2\n{new_password}\n"));
}

#[test]
fn update_unknown_entry() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["update", "bogus", "user", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("no entry 'bogus'"));
}

#[test]
fn remove_with_yes() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    pw(&vault)
        .args(["remove", "foo", "--yes"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("Removed entry 'foo'"));

    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("no entry 'foo'"));
}

#[test]
fn remove_confirmed_interactively() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    // First stdin line answers the confirmation, the second is the passphrase.
    pw(&vault)
        .args(["remove", "foo"])
        .write_stdin(format!("y\n{PASSPHRASE}"))
        .assert()
        .success()
        .stdout(contains("Removed entry 'foo'"));
}

#[test]
fn remove_aborts_without_confirmation() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    pw(&vault)
        .args(["remove", "foo"])
        .write_stdin("n\n")
        .assert()
        .failure()
        .stderr(contains("Aborted"));

    // The entry is still there.
    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
}

#[test]
fn list_shows_vault_path_and_filters() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");
    add_entry(&vault, "bar", "user2");

    pw(&vault)
        .arg("list")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(
            contains("Vault: ")
                .and(contains("(2 entries)"))
                .and(contains("foo: user1"))
                .and(contains("bar: user2")),
        );

    pw(&vault)
        .args(["list", "FO"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("foo: user1").and(contains("bar").not()));
}

#[test]
fn wrong_passphrase() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .arg("list")
        .write_stdin("not the passphrase\n")
        .assert()
        .failure()
        .stderr(contains("incorrect passphrase"));
}

#[test]
fn export_prints_the_vault_as_json() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let password = add_entry(&vault, "foo", "user1");

    pw(&vault)
        .arg("export")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains(r#""version":1"#).and(contains(format!(
            r#"{{"name":"foo","username":"user1","password":"{password}"}}"#
        ))))
        .stderr(contains("Warning"));
}

#[test]
fn url_is_stored_and_shown() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args([
            "add",
            "work-github",
            "alice",
            "--url",
            "github.com",
            "--show",
        ])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    // The url is persisted in the vault...
    pw(&vault)
        .arg("export")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains(r#""url":"github.com""#));
    // ...and surfaced (on stderr) by `get`.
    pw(&vault)
        .args(["get", "work-github", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stderr(contains("url: github.com"));
}

#[test]
fn realm_is_stored_and_shown() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args([
            "add",
            "example-admin",
            "alice",
            "--url",
            "example.com",
            "--realm",
            "Admin Area",
            "--show",
        ])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    pw(&vault)
        .arg("export")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains(r#""realm":"Admin Area""#));
    pw(&vault)
        .args(["show", "example-admin"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("url: example.com").and(contains("realm: Admin Area")));
}

/// A realm names one protection space *on a host*, so on its own it could only
/// ever match nothing. Refused at the command line rather than stored.
#[test]
fn realm_without_url_is_rejected() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["add", "site", "u", "--realm", "Admin", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure();
}

#[test]
fn update_without_realm_clears_it() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args([
            "add",
            "site",
            "u",
            "--url",
            "example.com",
            "--realm",
            "Admin",
            "--show",
        ])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    // Keeping the url but omitting --realm clears the realm alone, turning a
    // realm-scoped entry back into a wildcard over its host.
    pw(&vault)
        .args(["update", "site", "u", "--url", "example.com", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    pw(&vault)
        .arg("export")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains(r#""url":"example.com""#).and(contains(r#""realm":"#).not()));
}

#[test]
fn update_without_url_clears_it() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["add", "site", "u", "--url", "example.com", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    // Omitting --url on update clears it, the same way omitting the username
    // clears the username.
    pw(&vault)
        .args(["update", "site", "u", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();
    pw(&vault)
        .arg("export")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains(r#""url":"#).not());
}

#[test]
fn update_keep_password_changes_metadata_only() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let password = add_entry(&vault, "foo", "user1");

    // Re-point the entry at a site and relabel it, keeping the password.
    pw(&vault)
        .args([
            "update",
            "foo",
            "user2",
            "--url",
            "github.com",
            "--keep-password",
        ])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("password unchanged"));

    // The username and url changed; the original password is intact.
    pw(&vault)
        .args(["get", "foo", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(format!("user2\n{password}\n"))
        .stderr(contains("url: github.com"));
}

#[test]
fn update_keep_password_rejects_input_password() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");
    // --keep-password and --input-password contradict each other.
    pw(&vault)
        .args(["update", "foo", "--keep-password", "--input-password"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure();
}

#[test]
fn backup_is_kept_after_rewrite() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "foo", "user1");

    let backup = dir.path().join("pw.scrypt.bak");
    assert!(backup.exists());

    // The backup holds the previous generation: an empty vault.
    pw(&backup)
        .arg("list")
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(contains("(0 entries)"));
}

#[test]
fn rejects_control_characters_in_name() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["add", "bad\x1bname", "user", "--show"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("invalid entry name"));
}

#[test]
fn generate_prints_password_of_requested_length() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt"); // not created; generate is stateless
    let assert = pw(&vault)
        .args(["generate", "--password-length", "32", "--show"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.trim_end().chars().count(), 32);
}

#[test]
fn generate_rejects_bad_charset() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("pw.scrypt");
    pw(&vault)
        .args(["generate", "--password-charset", "aaa", "--show"])
        .assert()
        .failure()
        .stderr(contains("invalid password charset"));

    pw(&vault)
        .args(["generate", "--password-charset", "abca", "--show"])
        .assert()
        .failure()
        .stderr(contains("must not contain duplicate characters"));
}

#[test]
fn show_prints_attributes_without_password() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args([
            "add",
            "work-github",
            "alice",
            "--url",
            "github.com",
            "--show",
        ])
        .write_stdin(PASSPHRASE)
        .assert()
        .success();

    pw(&vault)
        .args(["show", "work-github"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(
            contains("name: work-github")
                .and(contains("username: alice"))
                .and(contains("url: github.com")),
        );
}

#[test]
fn show_omits_absent_username_and_url() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    add_entry(&vault, "bare", "");

    pw(&vault)
        .args(["show", "bare"])
        .write_stdin(PASSPHRASE)
        .assert()
        .success()
        .stdout(
            contains("name: bare")
                .and(contains("username").not())
                .and(contains("url").not()),
        );
}

#[test]
fn show_fails_for_unknown_entry() {
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    pw(&vault)
        .args(["show", "bogus"])
        .write_stdin(PASSPHRASE)
        .assert()
        .failure()
        .stderr(contains("no entry 'bogus'"));
}

#[cfg(unix)]
#[test]
fn vault_created_with_restrictive_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let vault = init_vault(&dir);
    let mode = std::fs::metadata(&vault).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
