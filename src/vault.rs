//! Encrypted vault storage: the JSON envelope inside the scrypt format,
//! with atomic writes and restrictive permissions (PLAN.md §2.2, H-1, H-2).
//!
//! This module never prompts and never assumes a terminal: the passphrase
//! enters as a [`Passphrase`] parameter. [`load`] is strictly read-only.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::scrypt_format::{self, Params};
use crate::PasswordEntry;

/// Version of the JSON envelope inside the encrypted file. Bare arrays
/// written by pw <= 0.1.x are still accepted on read (PLAN.md §2.2).
const ENVELOPE_VERSION: u32 = 1;

/// The master passphrase. Zeroized on drop, redacted by `Debug`.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn new(passphrase: String) -> Self {
        Passphrase(Zeroizing::new(passphrase))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for Passphrase {
    fn from(passphrase: String) -> Self {
        Passphrase::new(passphrase)
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase([redacted])")
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("cannot read {file}: {source}")]
    Read {
        file: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write {file}: {source}")]
    Write {
        file: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Format(#[from] scrypt_format::Error),
    #[error("invalid vault content")]
    InvalidJson(#[source] serde_json::Error),
    #[error("vault format version {0} is newer than this version of MyPass understands")]
    UnsupportedVersion(u32),
}

#[derive(Serialize)]
struct Envelope<'a> {
    version: u32,
    entries: &'a [PasswordEntry],
}

#[derive(Deserialize)]
#[serde(untagged)]
enum VaultJson {
    Envelope {
        version: u32,
        entries: Vec<PasswordEntry>,
    },
    /// Bare array written by pw <= 0.1.x; upgraded to the envelope on the
    /// next [`store`].
    Legacy(Vec<PasswordEntry>),
}

/// Serialize entries to the JSON envelope — exactly what [`store`] encrypts.
pub fn to_json(entries: &[PasswordEntry]) -> Result<Zeroizing<String>, Error> {
    serde_json::to_string(&Envelope {
        version: ENVELOPE_VERSION,
        entries,
    })
    .map(Zeroizing::new)
    .map_err(Error::InvalidJson)
}

/// Decrypt and parse the vault. Read-only: never creates, locks or touches
/// the file.
pub fn load(file: &Path, passphrase: &Passphrase) -> Result<Vec<PasswordEntry>, Error> {
    let data = fs::read(file).map_err(|source| Error::Read {
        file: file.to_path_buf(),
        source,
    })?;
    let plaintext = scrypt_format::decrypt(&data, passphrase.as_bytes())?;
    // On parse failure the decrypted bytes are deliberately not included in
    // the error (serde_json errors carry positions, not data).
    let parsed: VaultJson = serde_json::from_slice(&plaintext).map_err(Error::InvalidJson)?;
    match parsed {
        VaultJson::Envelope {
            version: ENVELOPE_VERSION,
            entries,
        } => Ok(entries),
        VaultJson::Envelope { version, .. } => Err(Error::UnsupportedVersion(version)),
        VaultJson::Legacy(entries) => Ok(entries),
    }
}

/// Encrypt and write the vault atomically.
///
/// The ciphertext goes to `<file>.tmp` (created exclusively, `0o600` on
/// Unix) which is fsynced and then renamed over the target; an existing
/// vault is first copied to `<file>.bak`. A crash at any point leaves the
/// target as either the complete old or the complete new vault, never
/// truncated.
///
/// The temporary file must live next to the target (the rename may not
/// cross filesystems), and its name is deterministic so sandbox policies
/// (e.g. AppArmor) can allow exactly `<file>`, `<file>.tmp` and
/// `<file>.bak` instead of a wildcard.
pub fn store(
    file: &Path,
    passphrase: &Passphrase,
    entries: &[PasswordEntry],
    params: &Params,
) -> Result<(), Error> {
    let plaintext = to_json(entries)?;
    let ciphertext = scrypt_format::encrypt(plaintext.as_bytes(), passphrase.as_bytes(), params)?;

    let write_err = |source| Error::Write {
        file: file.to_path_buf(),
        source,
    };
    let dir = match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let tmp_path = temp_path(file);

    // Remove a stale temp file from a crashed previous run, then create
    // exclusively so an existing file (or symlink) is never followed.
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(write_err(e)),
    }
    let mut open_options = fs::OpenOptions::new();
    open_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }

    let result = (|| {
        let mut tmp = open_options.open(&tmp_path)?;
        tmp.write_all(&ciphertext)?;
        tmp.sync_all()?;

        if file.exists() {
            let bak = backup_path(file);
            fs::copy(file, &bak)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&bak, fs::Permissions::from_mode(0o600))?;
            }
        }

        fs::rename(&tmp_path, file)?;
        #[cfg(unix)]
        fs::File::open(dir).and_then(|d| d.sync_all())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result.map_err(write_err)
}

/// `<file>.tmp` next to the vault, e.g. `pw.scrypt` -> `pw.scrypt.tmp`.
fn temp_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// `<file>.bak` next to the vault, e.g. `pw.scrypt` -> `pw.scrypt.bak`.
pub fn backup_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".bak");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "test passphrase";
    // Small KDF parameters so debug-mode tests stay fast.
    const TEST_PARAMS: Params = Params {
        log_n: 12,
        r: 8,
        p: 1,
    };

    fn passphrase() -> Passphrase {
        Passphrase::new(PASSPHRASE.to_string())
    }

    fn entry(name: &str, password: &str) -> PasswordEntry {
        PasswordEntry {
            name: name.to_string(),
            username: format!("{name}-user"),
            password: password.into(),
            url: None,
            realm: None,
        }
    }

    fn vault_file(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("pw.scrypt")
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        let entries = vec![entry("a", "pw-a"), entry("b", "pw-b")];
        store(&file, &passphrase(), &entries, &TEST_PARAMS).unwrap();
        assert_eq!(load(&file, &passphrase()).unwrap(), entries);
    }

    #[test]
    fn round_trip_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        store(&file, &passphrase(), &[], &TEST_PARAMS).unwrap();
        assert_eq!(load(&file, &passphrase()).unwrap(), Vec::new());
    }

    #[test]
    fn wrong_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        store(&file, &passphrase(), &[], &TEST_PARAMS).unwrap();
        let err = load(&file, &Passphrase::new("wrong".to_string())).unwrap_err();
        assert!(matches!(
            err,
            Error::Format(scrypt_format::Error::WrongPassphrase)
        ));
    }

    #[test]
    fn missing_file_is_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(&vault_file(&dir), &passphrase()).unwrap_err();
        assert!(matches!(err, Error::Read { .. }));
    }

    #[test]
    fn reads_legacy_bare_array() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        let legacy = br#"[{"name":"a","username":"a-user","password":"pw-a"}]"#;
        let data = scrypt_format::encrypt(legacy, PASSPHRASE.as_bytes(), &TEST_PARAMS).unwrap();
        fs::write(&file, data).unwrap();
        assert_eq!(
            load(&file, &passphrase()).unwrap(),
            vec![entry("a", "pw-a")]
        );
    }

    #[test]
    fn rejects_newer_envelope_version() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        let future = br#"{"version":2,"entries":[],"url_field_or_whatever":true}"#;
        let data = scrypt_format::encrypt(future, PASSPHRASE.as_bytes(), &TEST_PARAMS).unwrap();
        fs::write(&file, data).unwrap();
        let err = load(&file, &passphrase()).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(2)));
    }

    #[test]
    fn rejects_garbage_json() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        let data =
            scrypt_format::encrypt(b"not json", PASSPHRASE.as_bytes(), &TEST_PARAMS).unwrap();
        fs::write(&file, data).unwrap();
        assert!(matches!(
            load(&file, &passphrase()).unwrap_err(),
            Error::InvalidJson(_)
        ));
    }

    #[test]
    fn writes_envelope_not_bare_array() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        store(&file, &passphrase(), &[entry("a", "pw-a")], &TEST_PARAMS).unwrap();
        let data = fs::read(&file).unwrap();
        let plain = scrypt_format::decrypt(&data, PASSPHRASE.as_bytes()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["entries"][0]["name"], "a");
    }

    #[cfg(unix)]
    #[test]
    fn vault_created_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        store(&file, &passphrase(), &[], &TEST_PARAMS).unwrap();
        assert_eq!(mode(&file), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn load_works_on_read_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        store(&file, &passphrase(), &[], &TEST_PARAMS).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(load(&file, &passphrase()).unwrap(), Vec::new());
    }

    #[test]
    fn overwrite_keeps_backup_of_previous_vault() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        let old = vec![entry("old", "pw-old")];
        let new = vec![entry("new", "pw-new")];
        store(&file, &passphrase(), &old, &TEST_PARAMS).unwrap();
        store(&file, &passphrase(), &new, &TEST_PARAMS).unwrap();

        assert_eq!(load(&file, &passphrase()).unwrap(), new);
        let bak = backup_path(&file);
        assert_eq!(load(&bak, &passphrase()).unwrap(), old);
        #[cfg(unix)]
        assert_eq!(mode(&bak), 0o600);
    }

    #[test]
    fn failed_store_leaves_existing_vault_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        let entries = vec![entry("a", "pw-a")];
        store(&file, &passphrase(), &entries, &TEST_PARAMS).unwrap();

        let bad_params = Params {
            log_n: 0,
            r: 8,
            p: 1,
        };
        let err = store(&file, &passphrase(), &[], &bad_params).unwrap_err();
        assert!(matches!(err, Error::Format(_)));

        assert_eq!(load(&file, &passphrase()).unwrap(), entries);
        assert!(!backup_path(&file).exists());
        // No stray temp files left in the directory.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn store_uses_deterministic_temp_name_and_overwrites_stale_one() {
        let dir = tempfile::tempdir().unwrap();
        let file = vault_file(&dir);
        let tmp = temp_path(&file);
        assert_eq!(tmp, dir.path().join("pw.scrypt.tmp"));
        // A stale temp file from a crashed previous run must not block the
        // write, and must be gone afterwards.
        fs::write(&tmp, b"stale").unwrap();
        let entries = vec![entry("a", "pw-a")];
        store(&file, &passphrase(), &entries, &TEST_PARAMS).unwrap();
        assert!(!tmp.exists());
        assert_eq!(load(&file, &passphrase()).unwrap(), entries);
    }

    #[test]
    fn debug_redacts_passphrase() {
        assert_eq!(format!("{:?}", passphrase()), "Passphrase([redacted])");
    }
}
