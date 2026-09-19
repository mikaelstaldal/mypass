//! Interoperability between the native codec and the `scrypt` command-line
//! tool
//!
//! The known-answer tests run everywhere using a fixture generated once by
//! scrypt 1.3.2 (see tests/data/). The live round-trip tests additionally
//! require a real `scrypt` binary on PATH and are skipped with a notice if
//! it is absent.

use std::path::{Path, PathBuf};
use std::process::Command;

use mypass::scrypt_format::{self, Error, Params};

/// Must match how tests/data/known_answer.scrypt was generated:
/// `scrypt enc --logN 12 -r 8 -p 1 --passphrase file:<passphrase-file>`
const PASSPHRASE: &[u8] = b"correct horse battery staple";
const PLAINTEXT: &[u8] = br#"{"version":1,"entries":[]}"#;
const TEST_PARAMS: Params = Params {
    log_n: 12,
    r: 8,
    p: 1,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

#[test]
fn known_answer_decrypts() {
    let data = std::fs::read(fixture("known_answer.scrypt")).unwrap();
    assert_eq!(data.len(), scrypt_format::OVERHEAD + PLAINTEXT.len());
    let plain = scrypt_format::decrypt(&data, PASSPHRASE).unwrap();
    assert_eq!(plain.as_slice(), PLAINTEXT);
}

#[test]
fn known_answer_rejects_wrong_passphrase() {
    let data = std::fs::read(fixture("known_answer.scrypt")).unwrap();
    assert_eq!(
        scrypt_format::decrypt(&data, b"wrong").unwrap_err(),
        Error::WrongPassphrase
    );
}

fn scrypt_tool_available() -> bool {
    match Command::new("scrypt").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(_) => {
            eprintln!("skipping live interop test: no `scrypt` binary on PATH");
            false
        }
    }
}

#[test]
fn scrypt_tool_decrypts_our_output() {
    if !scrypt_tool_available() {
        return;
    }
    let tmp = assert_fs::TempDir::new().unwrap();
    let pass_file = tmp.path().join("pass");
    let enc_file = tmp.path().join("vault.scrypt");
    std::fs::write(&pass_file, PASSPHRASE).unwrap();
    let data = scrypt_format::encrypt(PLAINTEXT, PASSPHRASE, &TEST_PARAMS).unwrap();
    std::fs::write(&enc_file, &data).unwrap();

    let output = Command::new("scrypt")
        .arg("dec")
        .arg("--passphrase")
        .arg(format!("file:{}", pass_file.display()))
        .arg(&enc_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "scrypt dec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, PLAINTEXT);
}

#[test]
fn we_decrypt_scrypt_tool_output() {
    if !scrypt_tool_available() {
        return;
    }
    let tmp = assert_fs::TempDir::new().unwrap();
    let pass_file = tmp.path().join("pass");
    let plain_file = tmp.path().join("plain");
    let enc_file = tmp.path().join("vault.scrypt");
    std::fs::write(&pass_file, PASSPHRASE).unwrap();
    std::fs::write(&plain_file, PLAINTEXT).unwrap();

    let status = Command::new("scrypt")
        .arg("enc")
        .arg("--logN")
        .arg("12")
        .arg("-r")
        .arg("8")
        .arg("-p")
        .arg("1")
        .arg("--passphrase")
        .arg(format!("file:{}", pass_file.display()))
        .arg(&plain_file)
        .arg(&enc_file)
        .status()
        .unwrap();
    assert!(status.success(), "scrypt enc failed");

    let data = std::fs::read(&enc_file).unwrap();
    let plain = scrypt_format::decrypt(&data, PASSPHRASE).unwrap();
    assert_eq!(plain.as_slice(), PLAINTEXT);
}
