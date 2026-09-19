//! # MyPass
//!
//! A command line password manager.
//!
//! Layering: [`scrypt_format`] is the pure byte codec, [`vault`] is encrypted
//! file storage, and this module holds the domain operations. Nothing here
//! ever prompts or assumes a terminal — the passphrase enters every operation
//! as a [`Passphrase`] parameter, so the same functions serve the CLI and any
//! future non-interactive host.

pub mod scrypt_format;
pub mod vault;

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use rand::rngs::SysRng;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use scrypt_format::Params;
pub use vault::Passphrase;

/// Longest accepted entry name or username, in characters.
pub const MAX_NAME_LEN: usize = 256;
/// Longest password [`generate_password`] will produce.
pub const MAX_PASSWORD_LEN: u32 = 1024;

#[derive(thiserror::Error, Debug)]
pub enum MyPassError {
    #[error("no vault at {0} - run `mypass init`")]
    FileNotFound(PathBuf),
    #[error("vault {0} already exists")]
    FileAlreadyExists(PathBuf),
    #[error("incorrect passphrase")]
    WrongPassphrase,
    #[error("no entry '{name}' in {file} - try `mypass list`")]
    NotFound { name: String, file: PathBuf },
    #[error("entry '{name}' already exists in {file} - use `mypass update`")]
    AlreadyExists { name: String, file: PathBuf },
    #[error("invalid {what}: {reason}")]
    InvalidInput { what: &'static str, reason: String },
    #[error(transparent)]
    Io(vault::Error),
    #[error("cannot use vault {file}")]
    CorruptVault {
        file: PathBuf,
        #[source]
        source: vault::Error,
    },
}

/// A stored password: zeroized on drop, redacted by `Debug`, serialized
/// transparently as a JSON string.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    /// Named so that every place the secret leaves the type is greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Secret(value.to_string())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordEntry {
    pub name: String,
    pub username: String,
    pub password: Secret,
    /// Optional site the entry is for. It is the sole association between an
    /// entry and a website: the browser integration releases this entry to a
    /// visited origin when the origin's host matches the `url`'s host. An entry
    /// must have a `url` set to be usable in a web browser; the entry `name` is
    /// never matched against the visited host. May be a bare hostname
    /// (`github.com`) or a full URL (`https://github.com/login`); only the host
    /// part is used for matching.
    /// Absent on entries written before this field existed, and not serialized
    /// when absent, so url-less entries stay byte-identical to the pre-`url`
    /// format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Optional HTTP-authentication realm the entry is for, narrowing `url` to
    /// a single protection space. A site can run several realms — each with
    /// its own username — under one host, which the host part alone cannot
    /// tell apart; naming the realm here makes the match unambiguous.
    ///
    /// Only the browser integration's HTTP-authentication path consults it; a
    /// form fill ignores it, since a login form belongs to no protection
    /// space. An entry with no realm is a wildcard, matching any realm on its
    /// `url` host — which is what every entry written before this field
    /// existed is. Meaningless without a `url`, and rejected without one.
    /// Not serialized when absent, so realm-less entries stay byte-identical
    /// to the pre-`realm` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

/// Create a new empty vault. Fails if the file already exists.
pub fn init(file: &Path, passphrase: &Passphrase, params: &Params) -> Result<(), MyPassError> {
    if file.exists() {
        return Err(MyPassError::FileAlreadyExists(file.to_path_buf()));
    }
    store(file, passphrase, &[], params)
}

/// Look up the entry named `name`.
pub fn get(file: &Path, passphrase: &Passphrase, name: &str) -> Result<PasswordEntry, MyPassError> {
    let entries = load(file, passphrase)?;
    entries
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| MyPassError::NotFound {
            name: name.to_string(),
            file: file.to_path_buf(),
        })
}

/// All entries in the vault.
pub fn list(file: &Path, passphrase: &Passphrase) -> Result<Vec<PasswordEntry>, MyPassError> {
    load(file, passphrase)
}

/// Add a new entry. Fails if an entry with the same name exists.
pub fn add(
    file: &Path,
    passphrase: &Passphrase,
    new_entry: PasswordEntry,
    params: &Params,
) -> Result<(), MyPassError> {
    validate_entry(&new_entry)?;
    let mut entries = load(file, passphrase)?;
    if entries.iter().any(|e| e.name == new_entry.name) {
        return Err(MyPassError::AlreadyExists {
            name: new_entry.name.clone(),
            file: file.to_path_buf(),
        });
    }
    entries.push(new_entry);
    store(file, passphrase, &entries, params)
}

/// Replace the username, password and `url` of an existing entry.
pub fn update(
    file: &Path,
    passphrase: &Passphrase,
    new_entry: PasswordEntry,
    params: &Params,
) -> Result<(), MyPassError> {
    validate_entry(&new_entry)?;
    let mut entries = load(file, passphrase)?;
    let Some(entry) = entries.iter_mut().find(|e| e.name == new_entry.name) else {
        return Err(MyPassError::NotFound {
            name: new_entry.name.clone(),
            file: file.to_path_buf(),
        });
    };
    *entry = new_entry;
    store(file, passphrase, &entries, params)
}

/// Replace the username, `url` and `realm` of an existing entry while keeping
/// its current password, so the user can re-point an entry at another site (or
/// relabel it) without rotating the secret. Fails if no entry is named `name`.
pub fn update_keep_password(
    file: &Path,
    passphrase: &Passphrase,
    name: &str,
    username: String,
    url: Option<String>,
    realm: Option<String>,
    params: &Params,
) -> Result<(), MyPassError> {
    validate_name(name)?;
    validate_username(&username)?;
    validate_site(url.as_deref(), realm.as_deref())?;
    let mut entries = load(file, passphrase)?;
    let Some(entry) = entries.iter_mut().find(|e| e.name == name) else {
        return Err(MyPassError::NotFound {
            name: name.to_string(),
            file: file.to_path_buf(),
        });
    };
    entry.username = username;
    entry.url = url;
    entry.realm = realm;
    store(file, passphrase, &entries, params)
}

/// Remove the entry named `name`.
pub fn remove(
    file: &Path,
    passphrase: &Passphrase,
    name: &str,
    params: &Params,
) -> Result<(), MyPassError> {
    let mut entries = load(file, passphrase)?;
    let original_len = entries.len();
    entries.retain(|e| e.name != name);
    if entries.len() == original_len {
        return Err(MyPassError::NotFound {
            name: name.to_string(),
            file: file.to_path_buf(),
        });
    }
    store(file, passphrase, &entries, params)
}

/// The decrypted vault as JSON (the same envelope that is stored encrypted),
/// for backup and migration.
pub fn export(file: &Path, passphrase: &Passphrase) -> Result<Zeroizing<String>, MyPassError> {
    let entries = load(file, passphrase)?;
    vault::to_json(&entries).map_err(|e| vault_err(file, e))
}

fn load(file: &Path, passphrase: &Passphrase) -> Result<Vec<PasswordEntry>, MyPassError> {
    if !file.exists() {
        return Err(MyPassError::FileNotFound(file.to_path_buf()));
    }
    vault::load(file, passphrase).map_err(|e| vault_err(file, e))
}

fn store(
    file: &Path,
    passphrase: &Passphrase,
    entries: &[PasswordEntry],
    params: &Params,
) -> Result<(), MyPassError> {
    vault::store(file, passphrase, entries, params).map_err(|e| vault_err(file, e))
}

fn vault_err(file: &Path, err: vault::Error) -> MyPassError {
    match err {
        vault::Error::Format(scrypt_format::Error::WrongPassphrase) => MyPassError::WrongPassphrase,
        e @ (vault::Error::Read { .. } | vault::Error::Write { .. }) => MyPassError::Io(e),
        e => MyPassError::CorruptVault {
            file: file.to_path_buf(),
            source: e,
        },
    }
}

/// Returns true for Unicode bidirectional control and zero-width code points
/// that can reorder or disguise how text renders without being "control"
/// characters per [`char::is_control`] (a Trojan-Source / homoglyph style
/// display spoof). Used both to reject such characters on input and to
/// replace them on output.
pub fn is_display_spoofing_char(c: char) -> bool {
    matches!(c,
        // Bidirectional embeddings, overrides and isolates
        '\u{202A}'..='\u{202E}'   // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
        // Bidirectional marks
        | '\u{200E}' | '\u{200F}' // LRM, RLM
        | '\u{061C}'              // Arabic Letter Mark
        // Zero-width characters
        | '\u{200B}'              // Zero Width Space
        | '\u{200C}' | '\u{200D}' // ZWNJ, ZWJ
        | '\u{2060}'              // Word Joiner
        | '\u{FEFF}'              // Zero Width No-Break Space / BOM
    )
}

/// Entry names must be non-empty, at most [`MAX_NAME_LEN`] characters and
/// free of control, bidirectional and zero-width characters. Everything a
/// hostname can contain is allowed.
pub fn validate_name(name: &str) -> Result<(), MyPassError> {
    if name.is_empty() {
        return Err(MyPassError::InvalidInput {
            what: "entry name",
            reason: "must not be empty".to_string(),
        });
    }
    validate_text("entry name", name)
}

/// Usernames may be empty, but obey the same length and character rules as
/// entry names.
pub fn validate_username(username: &str) -> Result<(), MyPassError> {
    validate_text("username", username)
}

/// The optional `url` matching hint, when present, must be non-empty and obey
/// the same length and character rules as entry names. Callers map "no url"
/// to `None`, so an empty string is rejected rather than stored.
pub fn validate_url(url: &str) -> Result<(), MyPassError> {
    if url.is_empty() {
        return Err(MyPassError::InvalidInput {
            what: "url",
            reason: "must not be empty".to_string(),
        });
    }
    validate_text("url", url)
}

/// The optional `realm` matching hint, when present, must be non-empty and
/// obey the same length and character rules as entry names. Callers map "no
/// realm" to `None`, so an empty string is rejected rather than stored.
pub fn validate_realm(realm: &str) -> Result<(), MyPassError> {
    if realm.is_empty() {
        return Err(MyPassError::InvalidInput {
            what: "realm",
            reason: "must not be empty".to_string(),
        });
    }
    validate_text("realm", realm)
}

/// Validate the pair of site-matching hints. A `realm` names one protection
/// space *on a host*, so it can only narrow a `url`; on its own it would
/// silently never match anything, which is worth refusing rather than storing.
fn validate_site(url: Option<&str>, realm: Option<&str>) -> Result<(), MyPassError> {
    if let Some(url) = url {
        validate_url(url)?;
    }
    if let Some(realm) = realm {
        validate_realm(realm)?;
        if url.is_none() {
            return Err(MyPassError::InvalidInput {
                what: "realm",
                reason: "needs a url: a realm names a protection space on a site".to_string(),
            });
        }
    }
    Ok(())
}

/// Validate the user-supplied fields of an entry before it is stored.
fn validate_entry(entry: &PasswordEntry) -> Result<(), MyPassError> {
    validate_name(&entry.name)?;
    validate_username(&entry.username)?;
    validate_site(entry.url.as_deref(), entry.realm.as_deref())
}

fn validate_text(what: &'static str, value: &str) -> Result<(), MyPassError> {
    if value.chars().count() > MAX_NAME_LEN {
        return Err(MyPassError::InvalidInput {
            what,
            reason: format!("longer than {MAX_NAME_LEN} characters"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(MyPassError::InvalidInput {
            what,
            reason: "contains control characters".to_string(),
        });
    }
    if value.chars().any(is_display_spoofing_char) {
        return Err(MyPassError::InvalidInput {
            what,
            reason: "contains bidirectional or zero-width characters".to_string(),
        });
    }
    Ok(())
}

/// Extract the hostname from a web origin, applying the eligibility rules of
/// the browser integration: only `https:`
/// origins are accepted, plus `http://localhost` and `http://127.0.0.1` for
/// local development. The returned hostname is IDNA/punycode-normalized and
/// lowercased. Any ineligible or unparsable origin yields `None` (mapped to
/// the `invalid-origin` error by the browser host); no other scheme,
/// including `http:` on a real host, `file:` or `moz-extension:`, is accepted.
pub fn origin_hostname(origin: &str) -> Option<String> {
    let (scheme, rest) = origin.split_once("://")?;
    let host = normalize_host(host_from_authority(rest))?;
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Some(host),
        "http" if host == "localhost" || host == "127.0.0.1" => Some(host),
        _ => None,
    }
}

/// Reduce the part of a URL after `scheme://` to its bare host: drop any
/// path/query/fragment, then any userinfo, then the port. A bracketed IPv6
/// literal is never an eligible host in this integration, so a plain
/// rightmost-colon split for the port is sufficient.
fn host_from_authority(after_scheme: &str) -> &str {
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// Entries that match `hostname`. An entry matches when the host part of its
/// `url` field equals the hostname (exact match) or is a parent domain of it
/// at a label boundary, climbing no further than the registrable domain
/// (eTLD+1, via the Public Suffix List). All values are IDNA/punycode-
/// normalized and compared case-insensitively, so `example.co.uk` matches
/// `login.example.co.uk` but `co.uk` matches nothing. Only entries with a
/// `url` set are eligible for web browser use; the entry `name` is never
/// matched against the hostname.
pub fn matching_entries<'a>(
    hostname: &str,
    entries: &'a [PasswordEntry],
) -> Vec<&'a PasswordEntry> {
    let Some(host) = normalize_host(hostname) else {
        return Vec::new();
    };
    // The registrable domain bounds how far a parent-domain match may climb.
    // A host with no registrable domain — a bare IP, `localhost`, or a public
    // suffix itself — admits only an exact match.
    let min_labels = psl::domain_str(&host).map_or_else(|| label_count(&host), label_count);
    let candidate_matches =
        |candidate: Option<String>| candidate.is_some_and(|c| host_matches(&host, &c, min_labels));
    entries
        .iter()
        .filter(|e| candidate_matches(e.url.as_deref().and_then(url_host)))
        .collect()
}

/// Entries releasable to the HTTP-authentication protection space
/// (`hostname`, `realm`): those whose `url` host is *exactly* `hostname`, with
/// no parent-domain match, narrowed by `realm`.
///
/// [`matching_entries`] deliberately accepts a parent domain, which is right
/// for a fill the user asks for on the page in front of them. It is wrong for a
/// release with no user gesture behind it — HTTP authentication — where a
/// subdomain under someone else's control (a dangling-CNAME takeover, shared
/// hosting, one tenant of a multi-tenant apex) could otherwise collect the
/// parent domain's password silently, with no dialog to notice. Exact matching
/// is also how HTTP authentication scopes credentials in the first place: a
/// protection space is a single origin, never a domain tree.
///
/// The realm completes that protection space. Among the entries on the host:
///
/// - if any names this exact realm, only those are released — the site said
///   which space it is challenging for, and the vault says which entry belongs
///   to it, so there is nothing to guess at;
/// - otherwise the entries naming *no* realm are released, since an untagged
///   entry is a wildcard over its host. Every entry written before the field
///   existed is untagged, so an unrealmed vault behaves exactly as before;
/// - entries naming a *different* realm are never released, whether or not
///   anything else matched. Being told the credential is for another space is
///   reason enough not to send it to this one.
///
/// Realms are compared as exact strings, as the protocol defines them: an
/// opaque quoted string, not a case-insensitive token or a domain. A challenge
/// carrying no realm (`None`) therefore matches only untagged entries.
pub fn exactly_matching_entries<'a>(
    hostname: &str,
    realm: Option<&str>,
    entries: &'a [PasswordEntry],
) -> Vec<&'a PasswordEntry> {
    let Some(host) = normalize_host(hostname) else {
        return Vec::new();
    };
    let on_host: Vec<&PasswordEntry> = entries
        .iter()
        .filter(|e| {
            e.url
                .as_deref()
                .and_then(url_host)
                .is_some_and(|c| c == host)
        })
        .collect();
    let named: Vec<&PasswordEntry> = match realm {
        Some(realm) => on_host
            .iter()
            .copied()
            .filter(|e| e.realm.as_deref() == Some(realm))
            .collect(),
        None => Vec::new(),
    };
    if !named.is_empty() {
        return named;
    }
    on_host.into_iter().filter(|e| e.realm.is_none()).collect()
}

/// IDNA/punycode-normalize a hostname to lowercase ASCII, or `None` if it is
/// not a usable domain. `domain_to_ascii` already lowercases and rejects the
/// empty string and malformed labels.
fn normalize_host(host: &str) -> Option<String> {
    idna::domain_to_ascii(host).ok().filter(|h| !h.is_empty())
}

/// Extract and normalize the host from an entry's `url` field, which may be a
/// bare hostname (`github.com`), a host:port, or a full URL
/// (`https://github.com/login`). Unlike [`origin_hostname`] this places no
/// constraint on the scheme — it is a stored matching hint, not an incoming
/// request — so any scheme (or none) is accepted and only the host is kept.
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    normalize_host(host_from_authority(after_scheme))
}

fn label_count(domain: &str) -> usize {
    domain.split('.').filter(|label| !label.is_empty()).count()
}

/// Whether `name` (already normalized) matches `host` (already normalized):
/// an exact match, or a parent-domain match landing on a label boundary and
/// having at least `min_labels` labels so it never climbs past the
/// registrable domain.
fn host_matches(host: &str, name: &str, min_labels: usize) -> bool {
    if name == host {
        return true;
    }
    label_count(name) >= min_labels
        && host.len() > name.len()
        && host.ends_with(name)
        && host.as_bytes()[host.len() - name.len() - 1] == b'.'
}

/// Generate a random password of `length` characters from `charset`,
/// using a cryptographically secure generator. Charset characters are Unicode
/// scalar values, and each value must occur exactly once.
pub fn generate_password(length: u32, charset: &str) -> Result<Secret, MyPassError> {
    if length == 0 || length > MAX_PASSWORD_LEN {
        return Err(MyPassError::InvalidInput {
            what: "password length",
            reason: format!("must be between 1 and {MAX_PASSWORD_LEN}"),
        });
    }
    let chars: Vec<char> = charset.chars().collect();
    let unique: HashSet<char> = chars.iter().copied().collect();
    if unique.len() < 2 {
        return Err(MyPassError::InvalidInput {
            what: "password charset",
            reason: "must contain at least 2 distinct characters".to_string(),
        });
    }
    if unique.len() != chars.len() {
        return Err(MyPassError::InvalidInput {
            what: "password charset",
            reason: "must not contain duplicate characters".to_string(),
        });
    }
    let mut rng =
        ChaCha20Rng::try_from_rng(&mut SysRng).expect("failed to read from the OS random source");
    // random_range uses rejection sampling: no modulo bias.
    let password: String = (0..length)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect();
    Ok(Secret::new(password))
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

    fn new_vault(entries: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw.scrypt");
        init(&file, &passphrase(), &TEST_PARAMS).unwrap();
        for (name, password) in entries {
            add(&file, &passphrase(), entry(name, password), &TEST_PARAMS).unwrap();
        }
        (dir, file)
    }

    #[test]
    fn init_then_list_empty() {
        let (_dir, file) = new_vault(&[]);
        assert_eq!(list(&file, &passphrase()).unwrap(), Vec::new());
    }

    #[test]
    fn init_refuses_existing_file() {
        let (_dir, file) = new_vault(&[]);
        let err = init(&file, &passphrase(), &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, MyPassError::FileAlreadyExists(_)));
    }

    #[test]
    fn add_then_get() {
        let (_dir, file) = new_vault(&[("a", "pw-a"), ("b", "pw-b")]);
        let got = get(&file, &passphrase(), "b").unwrap();
        assert_eq!(got, entry("b", "pw-b"));
    }

    #[test]
    fn get_unknown_name() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        let err = get(&file, &passphrase(), "nope").unwrap_err();
        assert!(matches!(err, MyPassError::NotFound { name, .. } if name == "nope"));
    }

    #[test]
    fn add_duplicate_name() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        let err = add(&file, &passphrase(), entry("a", "other"), &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, MyPassError::AlreadyExists { name, .. } if name == "a"));
    }

    #[test]
    fn update_existing() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        update(&file, &passphrase(), entry("a", "pw-new"), &TEST_PARAMS).unwrap();
        assert_eq!(
            get(&file, &passphrase(), "a").unwrap().password,
            "pw-new".into()
        );
    }

    #[test]
    fn update_unknown_name() {
        let (_dir, file) = new_vault(&[]);
        let err = update(&file, &passphrase(), entry("a", "pw"), &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, MyPassError::NotFound { .. }));
    }

    #[test]
    fn remove_existing() {
        let (_dir, file) = new_vault(&[("a", "pw-a"), ("b", "pw-b")]);
        remove(&file, &passphrase(), "a", &TEST_PARAMS).unwrap();
        let names: Vec<String> = list(&file, &passphrase())
            .unwrap()
            .into_iter()
            .map(|e| e.name.clone())
            .collect();
        assert_eq!(names, vec!["b"]);
    }

    #[test]
    fn remove_unknown_name() {
        let (_dir, file) = new_vault(&[]);
        let err = remove(&file, &passphrase(), "a", &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, MyPassError::NotFound { .. }));
    }

    #[test]
    fn missing_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pw.scrypt");
        for err in [
            get(&file, &passphrase(), "a").unwrap_err(),
            list(&file, &passphrase()).map(|_| ()).unwrap_err(),
            add(&file, &passphrase(), entry("a", "pw"), &TEST_PARAMS).unwrap_err(),
        ] {
            assert!(matches!(err, MyPassError::FileNotFound(_)));
        }
    }

    #[test]
    fn wrong_passphrase_is_distinct() {
        let (_dir, file) = new_vault(&[]);
        let err = list(&file, &Passphrase::new("wrong".to_string())).unwrap_err();
        assert!(matches!(err, MyPassError::WrongPassphrase));
    }

    #[test]
    fn export_round_trips_as_json() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        let json = export(&file, &passphrase()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["entries"][0]["password"], "pw-a");
    }

    #[test]
    fn rejects_invalid_names() {
        let (_dir, file) = new_vault(&[]);
        for name in ["", "with\nnewline", "with\x1b[31mescape", &"x".repeat(257)] {
            let err = add(&file, &passphrase(), entry(name, "pw"), &TEST_PARAMS).unwrap_err();
            assert!(
                matches!(err, MyPassError::InvalidInput { .. }),
                "name {name:?}"
            );
        }
    }

    #[test]
    fn allows_hostname_names() {
        for name in [
            "example.com",
            "xn--bcher-kva.example",
            "sub.host-1.example.org",
        ] {
            assert!(validate_name(name).is_ok(), "name {name:?}");
        }
    }

    #[test]
    fn rejects_control_chars_in_username() {
        let (_dir, file) = new_vault(&[]);
        let bad = PasswordEntry {
            name: "a".to_string(),
            username: "user\r\n".to_string(),
            password: "pw".into(),
            url: None,
            realm: None,
        };
        let err = add(&file, &passphrase(), bad, &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, MyPassError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_bidi_and_zero_width_chars() {
        // Right-to-Left Override, Left-to-Right Isolate, Zero Width Space,
        // Zero Width Joiner and BOM must all be rejected in names and usernames.
        for spoof in [
            "a\u{202E}b",
            "a\u{2066}b",
            "a\u{200B}b",
            "a\u{200D}b",
            "a\u{FEFF}b",
        ] {
            assert!(
                matches!(validate_name(spoof), Err(MyPassError::InvalidInput { .. })),
                "name {spoof:?}"
            );
            assert!(
                matches!(
                    validate_username(spoof),
                    Err(MyPassError::InvalidInput { .. })
                ),
                "username {spoof:?}"
            );
        }
    }

    #[test]
    fn empty_username_is_allowed() {
        let (_dir, file) = new_vault(&[]);
        let e = PasswordEntry {
            name: "a".to_string(),
            username: String::new(),
            password: "pw".into(),
            url: None,
            realm: None,
        };
        add(&file, &passphrase(), e, &TEST_PARAMS).unwrap();
        assert_eq!(get(&file, &passphrase(), "a").unwrap().username, "");
    }

    #[test]
    fn generate_uses_charset_and_length() {
        let pw = generate_password(16, "0123456789").unwrap();
        assert_eq!(pw.expose().chars().count(), 16);
        assert!(pw.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_rejects_bad_input() {
        assert!(matches!(
            generate_password(0, "abc").unwrap_err(),
            MyPassError::InvalidInput {
                what: "password length",
                ..
            }
        ));
        assert!(matches!(
            generate_password(2000, "abc").unwrap_err(),
            MyPassError::InvalidInput {
                what: "password length",
                ..
            }
        ));
        for charset in ["", "a", "aaaa"] {
            assert!(matches!(
                generate_password(8, charset).unwrap_err(),
                MyPassError::InvalidInput {
                    what: "password charset",
                    ..
                }
            ));
        }

        for charset in ["aab", "😀😀😺"] {
            assert!(matches!(
                generate_password(8, charset).unwrap_err(),
                MyPassError::InvalidInput {
                    what: "password charset",
                    reason,
                } if reason == "must not contain duplicate characters"
            ));
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let e = entry("a", "super secret");
        let debug = format!("{e:?}");
        assert!(debug.contains("[redacted]"), "{debug}");
        assert!(!debug.contains("super secret"), "{debug}");
    }

    fn with_url(name: &str, url: &str) -> PasswordEntry {
        PasswordEntry {
            name: name.to_string(),
            username: "user".to_string(),
            password: "pw".into(),
            url: Some(url.to_string()),
            realm: None,
        }
    }

    /// Run `matching_entries` for `hostname` over entries whose `url` is each of
    /// `urls`. The entry name is deliberately unrelated to the host (matching is
    /// on `url` only), and the returned strings are the matched `url`s.
    fn matches(hostname: &str, urls: &[&str]) -> Vec<String> {
        let entries: Vec<PasswordEntry> = urls
            .iter()
            .enumerate()
            .map(|(i, u)| with_url(&format!("entry-{i}"), u))
            .collect();
        matching_entries(hostname, &entries)
            .into_iter()
            .filter_map(|e| e.url.clone())
            .collect()
    }

    /// The same, for the gesture-less path's stricter rule.
    fn matches_exactly(hostname: &str, urls: &[&str]) -> Vec<String> {
        let entries: Vec<PasswordEntry> = urls
            .iter()
            .enumerate()
            .map(|(i, u)| with_url(&format!("entry-{i}"), u))
            .collect();
        exactly_matching_entries(hostname, None, &entries)
            .into_iter()
            .filter_map(|e| e.url.clone())
            .collect()
    }

    fn with_realm(name: &str, url: &str, realm: Option<&str>) -> PasswordEntry {
        let mut entry = with_url(name, url);
        entry.realm = realm.map(str::to_string);
        entry
    }

    /// Run the protection-space match for `hostname`/`realm` and return the
    /// names of the entries released, in order.
    fn realm_matches(
        hostname: &str,
        realm: Option<&str>,
        entries: &[PasswordEntry],
    ) -> Vec<String> {
        exactly_matching_entries(hostname, realm, entries)
            .into_iter()
            .map(|e| e.name.clone())
            .collect()
    }

    #[test]
    fn matches_exact_hostname() {
        assert_eq!(matches("github.com", &["github.com"]), vec!["github.com"]);
    }

    #[test]
    fn exact_matching_rejects_parent_domain() {
        // The heart of it: a subdomain someone else may control must not be
        // able to collect the parent domain's credentials without a gesture.
        assert!(matches_exactly("evil.example.com", &["example.com"]).is_empty());
        // ...while the ordinary, user-driven fill still accepts it.
        assert_eq!(
            matches("evil.example.com", &["example.com"]),
            vec!["example.com"]
        );
    }

    #[test]
    fn exact_matching_accepts_only_the_same_host() {
        assert_eq!(
            matches_exactly("login.example.com", &["login.example.com"]),
            vec!["login.example.com"]
        );
        // Still normalized: case, IDNA, ports, full URLs and userinfo.
        assert_eq!(
            matches_exactly("github.com", &["GitHub.com"]),
            vec!["GitHub.com"]
        );
        assert_eq!(
            matches_exactly("github.com", &["https://user@github.com:8443/login"]),
            vec!["https://user@github.com:8443/login"]
        );
        assert_eq!(
            matches_exactly("xn--bcher-kva.example", &["bücher.example"]).len(),
            1
        );
        // Neither direction of a parent/child relation, and no unrelated host.
        assert!(matches_exactly("example.com", &["login.example.com"]).is_empty());
        assert!(matches_exactly("example.com", &["example.org"]).is_empty());
        assert!(matches_exactly("example.com", &[""]).is_empty());
    }

    #[test]
    fn matches_parent_domain_at_label_boundary() {
        assert_eq!(
            matches("login.example.co.uk", &["example.co.uk"]),
            vec!["example.co.uk"]
        );
        // A subdomain entry never matches a shorter requested host.
        assert!(matches("example.co.uk", &["login.example.co.uk"]).is_empty());
    }

    #[test]
    fn does_not_match_across_public_suffix() {
        // The registrable-domain cut-off stops `co.uk` / `com` matching, so a
        // shared suffix cannot leak credentials between sites.
        assert!(matches("login.example.co.uk", &["co.uk"]).is_empty());
        assert!(matches("github.com", &["com"]).is_empty());
    }

    #[test]
    fn does_not_match_non_boundary_or_sibling() {
        // Not a label boundary: `hub.com` is a suffix of `github.com` only as
        // a substring, never as a parent domain.
        assert!(matches("github.com", &["hub.com"]).is_empty());
        // A phishing host cannot borrow the victim's entry.
        assert!(matches("github.com.evil.example", &["github.com"]).is_empty());
        // ...and only `evil.example`'s own entry matches it.
        assert_eq!(
            matches("github.com.evil.example", &["evil.example"]),
            vec!["evil.example"]
        );
    }

    #[test]
    fn matches_case_insensitively() {
        assert_eq!(matches("github.com", &["GitHub.COM"]), vec!["GitHub.COM"]);
    }

    #[test]
    fn matches_after_idna_normalization() {
        // The request arrives as punycode (as a browser reports it); the entry
        // is named in Unicode. Both normalize to the same ASCII form.
        assert_eq!(
            matches("xn--bcher-kva.example", &["bücher.example"]),
            vec!["bücher.example"]
        );
    }

    #[test]
    fn localhost_matches_only_exactly() {
        assert_eq!(matches("localhost", &["localhost"]), vec!["localhost"]);
        assert!(matches("localhost", &["host"]).is_empty());
        assert_eq!(matches("127.0.0.1", &["127.0.0.1"]), vec!["127.0.0.1"]);
    }

    #[test]
    fn returns_all_candidates() {
        let got = matches(
            "login.github.com",
            &["github.com", "login.github.com", "other.com"],
        );
        assert_eq!(got, vec!["github.com", "login.github.com"]);
    }

    #[test]
    fn url_field_matches_when_name_does_not() {
        // The entry's name is not the hostname, but its url declares the site.
        let entries = vec![with_url("work-github", "github.com")];
        let got: Vec<String> = matching_entries("github.com", &entries)
            .into_iter()
            .map(|e| e.name.clone())
            .collect();
        assert_eq!(got, vec!["work-github"]);
    }

    #[test]
    fn entry_without_url_never_matches() {
        // An entry whose name is the hostname but which has no url is not
        // eligible for browser use.
        let entries = vec![PasswordEntry {
            name: "github.com".to_string(),
            username: "user".to_string(),
            password: "pw".into(),
            url: None,
            realm: None,
        }];
        assert!(matching_entries("github.com", &entries).is_empty());
    }

    #[test]
    fn name_is_not_matched_against_host() {
        // The name equals the host, but the url points elsewhere: no match.
        let entries = vec![with_url("github.com", "example.com")];
        assert!(matching_entries("github.com", &entries).is_empty());
    }

    #[test]
    fn url_field_accepts_full_url() {
        // A full URL is accepted; only its host is used for matching, and the
        // parent-domain rule still applies to subdomains of the request.
        let entries = vec![with_url("work", "https://github.com/login?next=/")];
        assert_eq!(matching_entries("login.github.com", &entries).len(), 1);
    }

    #[test]
    fn url_field_respects_public_suffix_boundary() {
        // A url of `co.uk` must not match across the registrable domain.
        let entries = vec![with_url("anything", "co.uk")];
        assert!(matching_entries("login.example.co.uk", &entries).is_empty());
    }

    #[test]
    fn url_field_does_not_match_unrelated_host() {
        let entries = vec![with_url("work", "github.com")];
        assert!(matching_entries("example.com", &entries).is_empty());
    }

    #[test]
    fn url_round_trips_and_is_omitted_when_absent() {
        let (_dir, file) = new_vault(&[("plain", "pw-plain")]);
        add(
            &file,
            &passphrase(),
            with_url("work", "github.com"),
            &TEST_PARAMS,
        )
        .unwrap();
        let json = export(&file, &passphrase()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        // A url-less entry carries no "url" key, so it stays byte-identical to
        // the pre-`url` on-disk format.
        assert!(value["entries"][0].get("url").is_none());
        // An entry with a url keeps it across the encrypt/decrypt round-trip.
        assert_eq!(value["entries"][1]["url"], "github.com");
        assert_eq!(
            get(&file, &passphrase(), "work").unwrap().url.as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn realm_selects_the_entry_naming_it() {
        let entries = vec![
            with_realm("admin", "example.com", Some("Admin")),
            with_realm("wiki", "example.com", Some("Wiki")),
        ];
        assert_eq!(
            realm_matches("example.com", Some("Admin"), &entries),
            ["admin"]
        );
        assert_eq!(
            realm_matches("example.com", Some("Wiki"), &entries),
            ["wiki"]
        );
    }

    #[test]
    fn a_realmed_entry_is_never_released_to_another_realm() {
        // Not even when nothing else matches: being told the credential
        // belongs to another protection space is reason enough to withhold it.
        let entries = vec![with_realm("admin", "example.com", Some("Admin"))];
        assert!(realm_matches("example.com", Some("Wiki"), &entries).is_empty());
        assert!(realm_matches("example.com", None, &entries).is_empty());
    }

    #[test]
    fn an_unrealmed_entry_is_a_wildcard_over_its_host() {
        // Every entry written before the field existed is untagged, so an old
        // vault must keep matching whatever realm the site challenges for.
        let entries = vec![with_realm("site", "example.com", None)];
        for realm in [Some("Admin"), Some("Wiki"), None] {
            assert_eq!(realm_matches("example.com", realm, &entries), ["site"]);
        }
    }

    #[test]
    fn a_named_realm_wins_over_the_wildcard() {
        // Both would do, but the specific one is what the site asked for, and
        // releasing only it is what turns two matches into no chooser at all.
        let entries = vec![
            with_realm("catch-all", "example.com", None),
            with_realm("admin", "example.com", Some("Admin")),
        ];
        assert_eq!(
            realm_matches("example.com", Some("Admin"), &entries),
            ["admin"]
        );
        // A realm no entry names falls back to the wildcard.
        assert_eq!(
            realm_matches("example.com", Some("Other"), &entries),
            ["catch-all"]
        );
    }

    #[test]
    fn realms_are_compared_as_exact_strings() {
        // The protocol makes a realm an opaque quoted string, not a
        // case-insensitive token.
        let entries = vec![with_realm("admin", "example.com", Some("Admin"))];
        assert!(realm_matches("example.com", Some("admin"), &entries).is_empty());
        assert!(realm_matches("example.com", Some("Admin "), &entries).is_empty());
    }

    #[test]
    fn realm_does_not_loosen_host_matching() {
        let entries = vec![with_realm("admin", "example.com", Some("Admin"))];
        assert!(realm_matches("evil.example.com", Some("Admin"), &entries).is_empty());
    }

    #[test]
    fn realm_is_ignored_by_the_gesture_driven_match() {
        // A login form belongs to no protection space, so a realm must not
        // keep an entry out of a fill the user clicked for.
        let entries = vec![with_realm("admin", "example.com", Some("Admin"))];
        assert_eq!(matching_entries("www.example.com", &entries).len(), 1);
    }

    #[test]
    fn realm_round_trips_and_is_omitted_when_absent() {
        let (_dir, file) = new_vault(&[]);
        add(
            &file,
            &passphrase(),
            with_realm("plain", "example.com", None),
            &TEST_PARAMS,
        )
        .unwrap();
        add(
            &file,
            &passphrase(),
            with_realm("admin", "example.com", Some("Admin")),
            &TEST_PARAMS,
        )
        .unwrap();
        let json = export(&file, &passphrase()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        // A realm-less entry carries no "realm" key, so it stays
        // byte-identical to the pre-`realm` on-disk format.
        assert!(value["entries"][0].get("realm").is_none());
        assert_eq!(value["entries"][1]["realm"], "Admin");
        assert_eq!(
            get(&file, &passphrase(), "admin").unwrap().realm.as_deref(),
            Some("Admin")
        );
    }

    #[test]
    fn rejects_a_realm_without_a_url() {
        // A realm names a protection space on a host; with no host it could
        // only ever match nothing, so it is refused rather than stored.
        let (_dir, file) = new_vault(&[]);
        let bad = PasswordEntry {
            name: "a".to_string(),
            username: String::new(),
            password: "pw".into(),
            url: None,
            realm: Some("Admin".to_string()),
        };
        let err = add(&file, &passphrase(), bad, &TEST_PARAMS).unwrap_err();
        assert!(matches!(
            err,
            MyPassError::InvalidInput { what: "realm", .. }
        ));
    }

    #[test]
    fn rejects_invalid_realm() {
        let (_dir, file) = new_vault(&[]);
        let bad = PasswordEntry {
            name: "a".to_string(),
            username: String::new(),
            password: "pw".into(),
            url: Some("example.com".to_string()),
            realm: Some("with\nnewline".to_string()),
        };
        let err = add(&file, &passphrase(), bad, &TEST_PARAMS).unwrap_err();
        assert!(matches!(
            err,
            MyPassError::InvalidInput { what: "realm", .. }
        ));
    }

    #[test]
    fn rejects_invalid_url() {
        let (_dir, file) = new_vault(&[]);
        let bad = PasswordEntry {
            name: "a".to_string(),
            username: String::new(),
            password: "pw".into(),
            url: Some("with\nnewline".to_string()),
            realm: None,
        };
        let err = add(&file, &passphrase(), bad, &TEST_PARAMS).unwrap_err();
        assert!(matches!(err, MyPassError::InvalidInput { what: "url", .. }));
    }

    #[test]
    fn update_keep_password_changes_metadata_only() {
        let (_dir, file) = new_vault(&[("a", "pw-a")]);
        update_keep_password(
            &file,
            &passphrase(),
            "a",
            "new-user".to_string(),
            Some("github.com".to_string()),
            Some("Admin".to_string()),
            &TEST_PARAMS,
        )
        .unwrap();
        let e = get(&file, &passphrase(), "a").unwrap();
        // The password is untouched; the username, url and realm are replaced.
        assert_eq!(e.password, "pw-a".into());
        assert_eq!(e.username, "new-user");
        assert_eq!(e.url.as_deref(), Some("github.com"));
        assert_eq!(e.realm.as_deref(), Some("Admin"));
    }

    #[test]
    fn update_keep_password_unknown_name() {
        let (_dir, file) = new_vault(&[]);
        let err = update_keep_password(
            &file,
            &passphrase(),
            "a",
            String::new(),
            None,
            None,
            &TEST_PARAMS,
        )
        .unwrap_err();
        assert!(matches!(err, MyPassError::NotFound { .. }));
    }

    #[test]
    fn origin_hostname_accepts_https() {
        assert_eq!(
            origin_hostname("https://github.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            origin_hostname("https://login.example.co.uk:8443").as_deref(),
            Some("login.example.co.uk")
        );
        assert_eq!(
            origin_hostname("https://GitHub.com").as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn origin_hostname_rejects_non_https() {
        for origin in [
            "http://github.com",
            "file:///etc/passwd",
            "moz-extension://abc/page.html",
            "ftp://example.com",
            "https://",
            "not-a-url",
        ] {
            assert!(origin_hostname(origin).is_none(), "origin {origin:?}");
        }
    }

    #[test]
    fn origin_hostname_allows_local_http_for_dev() {
        assert_eq!(
            origin_hostname("http://localhost:3000").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            origin_hostname("http://127.0.0.1:8080").as_deref(),
            Some("127.0.0.1")
        );
    }
}
