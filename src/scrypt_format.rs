//! The scrypt encrypted-data format, version 0.
//!
//! Byte-compatible with the `scrypt` command-line tool (Tarsnap's
//! `scryptenc`): files written by [`encrypt`] can be decrypted with
//! `scrypt dec`, and files written by `scrypt enc` can be read by
//! [`decrypt`]. This module does no I/O and knows nothing about the
//! vault contents.
//!
//! Layout:
//!
//! ```text
//! offset  size  field
//!  0       6    magic "scrypt"
//!  6       1    version = 0
//!  7       1    log2(N)
//!  8       4    r (big-endian u32)
//! 12       4    p (big-endian u32)
//! 16      32    salt
//! 48      16    SHA-256(bytes 0..48), first 16 bytes   (file-type checksum)
//! 64      32    HMAC-SHA256(key_hmac, bytes 0..64)     (passphrase check)
//! 96       n    AES-256-CTR(key_enc, nonce=0) ciphertext
//! 96+n    32    HMAC-SHA256(key_hmac, bytes 0..96+n)   (integrity)
//! ```
//!
//! where `dk = scrypt(passphrase, salt, N, r, p)` (64 bytes),
//! `key_enc = dk[0..32]` and `key_hmac = dk[32..64]`.

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, KeyInit, Mac};
use rand::rngs::SysRng;
use rand::TryRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

const MAGIC: &[u8; 6] = b"scrypt";
const VERSION: u8 = 0;
const SALT_LEN: usize = 32;

pub const HEADER_LEN: usize = 96;
pub const TRAILER_LEN: usize = 32;
/// Total size added to the plaintext by the format.
pub const OVERHEAD: usize = HEADER_LEN + TRAILER_LEN;

/// Cap on the memory the KDF may require when decrypting, so a corrupt or
/// malicious header cannot demand an enormous allocation (PLAN.md §2.1).
const MAX_KDF_MEMORY: u64 = 1 << 30; // 1 GiB
const MAX_LOG_N: u8 = 22;
const MAX_P: u32 = 1024;

/// scrypt KDF cost parameters as stored in the file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl Default for Params {
    /// Minimum automatic write-side defaults: `N = 2^17, r = 8, p = 1` (~128 MiB).
    fn default() -> Self {
        Params {
            log_n: 17,
            r: 8,
            p: 1,
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("not an scrypt-encrypted file")]
    NotScryptFormat,
    #[error("unsupported scrypt format version {0}")]
    UnsupportedVersion(u8),
    #[error("file is truncated")]
    Truncated,
    #[error("invalid scrypt parameters (log2(N)={log_n}, r={r}, p={p})")]
    InvalidParams { log_n: u8, r: u32, p: u32 },
    #[error(
        "scrypt parameters require too much memory (log2(N)={log_n}, r={r}; the limit is 1 GiB)"
    )]
    ParamsTooLarge { log_n: u8, r: u32 },
    #[error("incorrect passphrase")]
    WrongPassphrase,
    #[error("file is corrupt: integrity check failed")]
    Corrupt,
}

fn validate(params: &Params) -> Result<(), Error> {
    let Params { log_n, r, p } = *params;
    if log_n == 0
        || r == 0
        || p == 0
        || p > MAX_P
        // r * p < 2^30, required by the scrypt specification
        || (r as u64) * (p as u64) >= 1 << 30
    {
        return Err(Error::InvalidParams { log_n, r, p });
    }
    if log_n > MAX_LOG_N || (128u64 << log_n) * (r as u64) > MAX_KDF_MEMORY {
        return Err(Error::ParamsTooLarge { log_n, r });
    }
    Ok(())
}

/// Derive `key_enc || key_hmac` (64 bytes) from the passphrase and salt.
fn derive_keys(
    passphrase: &[u8],
    salt: &[u8],
    params: &Params,
) -> Result<Zeroizing<[u8; 64]>, Error> {
    let scrypt_params = scrypt::Params::new(params.log_n, params.r, params.p).map_err(|_| {
        Error::InvalidParams {
            log_n: params.log_n,
            r: params.r,
            p: params.p,
        }
    })?;
    let mut dk = Zeroizing::new([0u8; 64]);
    scrypt::scrypt(passphrase, salt, &scrypt_params, dk.as_mut()).map_err(|_| {
        Error::InvalidParams {
            log_n: params.log_n,
            r: params.r,
            p: params.p,
        }
    })?;
    Ok(dk)
}

fn hmac(key_hmac: &[u8], data: &[u8]) -> HmacSha256 {
    // HMAC accepts keys of any length; with a fixed 32-byte key this cannot fail.
    let mut mac = HmacSha256::new_from_slice(key_hmac).expect("HMAC key of any length is valid");
    mac.update(data);
    mac
}

/// Encrypt `plaintext` into a self-contained scrypt-format file image.
pub fn encrypt(plaintext: &[u8], passphrase: &[u8], params: &Params) -> Result<Vec<u8>, Error> {
    validate(params)?;
    let mut salt = [0u8; SALT_LEN];
    SysRng
        .try_fill_bytes(&mut salt)
        .expect("failed to read from the OS random source");
    encrypt_with_salt(plaintext, passphrase, params, &salt)
}

fn encrypt_with_salt(
    plaintext: &[u8],
    passphrase: &[u8],
    params: &Params,
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(params.log_n);
    out.extend_from_slice(&params.r.to_be_bytes());
    out.extend_from_slice(&params.p.to_be_bytes());
    out.extend_from_slice(salt);
    let checksum = Sha256::digest(&out);
    out.extend_from_slice(&checksum[..16]);

    let dk = derive_keys(passphrase, salt, params)?;
    let (key_enc, key_hmac) = dk.split_at(32);
    let header_mac = hmac(key_hmac, &out).finalize().into_bytes();
    out.extend_from_slice(&header_mac);
    debug_assert_eq!(out.len(), HEADER_LEN);

    out.extend_from_slice(plaintext);
    let mut cipher = Aes256Ctr::new_from_slices(key_enc, &[0u8; 16])
        .expect("AES-256 key and CTR IV sizes are fixed");
    // Encrypt in place: the plaintext bytes just appended are overwritten
    // with ciphertext, leaving no extra plaintext copy behind.
    cipher.apply_keystream(&mut out[HEADER_LEN..]);

    let trailer_mac = hmac(key_hmac, &out).finalize().into_bytes();
    out.extend_from_slice(&trailer_mac);
    Ok(out)
}

/// Read validated header parameters. These are authenticated only after decryption.
pub fn parameters(data: &[u8]) -> Result<Params, Error> {
    if data.len() < 7 || &data[..6] != MAGIC {
        return Err(Error::NotScryptFormat);
    }
    if data[6] != VERSION {
        return Err(Error::UnsupportedVersion(data[6]));
    }
    if data.len() < OVERHEAD {
        return Err(Error::Truncated);
    }
    let params = Params {
        log_n: data[7],
        r: u32::from_be_bytes(data[8..12].try_into().expect("fixed slice")),
        p: u32::from_be_bytes(data[12..16].try_into().expect("fixed slice")),
    };
    validate(&params)?;
    let checksum = Sha256::digest(&data[..48]);
    if checksum[..16] != data[48..64] {
        return Err(Error::NotScryptFormat);
    }

    Ok(params)
}

/// Calibrate CPU cost to approximately one second, keeping at least the
/// default memory and CPU cost. Parallelization cost avoids increasing memory
/// beyond the default 128 MiB. Calibration never uses a user's secrets.
pub fn tune() -> Result<Params, Error> {
    let mut params = Params::default();
    let started = std::time::Instant::now();
    drop(derive_keys(b"mypass calibration", &[0; SALT_LEN], &params)?);
    let seconds = started.elapsed().as_secs_f64().max(0.001);
    params.p = calibrated_p(seconds);
    validate(&params)?;
    Ok(params)
}

fn calibrated_p(seconds: f64) -> u32 {
    (1.0 / seconds).round().clamp(1.0, MAX_P as f64) as u32
}

/// Decrypt a scrypt-format file image. Errors distinguish "wrong file type"
/// ([`Error::NotScryptFormat`]), "wrong passphrase"
/// ([`Error::WrongPassphrase`]) and "damaged file" ([`Error::Corrupt`]).
pub fn decrypt(data: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let params = parameters(data)?;
    let salt = &data[16..48];
    let dk = derive_keys(passphrase, salt, &params)?;
    let (key_enc, key_hmac) = dk.split_at(32);

    hmac(key_hmac, &data[..64])
        .verify_slice(&data[64..HEADER_LEN])
        .map_err(|_| Error::WrongPassphrase)?;

    let body_end = data.len() - TRAILER_LEN;
    hmac(key_hmac, &data[..body_end])
        .verify_slice(&data[body_end..])
        .map_err(|_| Error::Corrupt)?;

    let mut plaintext = Zeroizing::new(data[HEADER_LEN..body_end].to_vec());
    let mut cipher = Aes256Ctr::new_from_slices(key_enc, &[0u8; 16])
        .expect("AES-256 key and CTR IV sizes are fixed");
    cipher.apply_keystream(&mut plaintext);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const PLAINTEXT: &[u8] = br#"{"version":1,"entries":[]}"#;
    // Small parameters so debug-mode tests stay fast; production defaults
    // are exercised by `Params::default()` validation below.
    const TEST_PARAMS: Params = Params {
        log_n: 12,
        r: 8,
        p: 1,
    };

    fn encrypted() -> Vec<u8> {
        encrypt(PLAINTEXT, PASSPHRASE, &TEST_PARAMS).unwrap()
    }

    #[test]
    fn round_trip() {
        let data = encrypted();
        assert_eq!(data.len(), OVERHEAD + PLAINTEXT.len());
        let plain = decrypt(&data, PASSPHRASE).unwrap();
        assert_eq!(plain.as_slice(), PLAINTEXT);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let data = encrypt(b"", PASSPHRASE, &TEST_PARAMS).unwrap();
        assert_eq!(data.len(), OVERHEAD);
        let plain = decrypt(&data, PASSPHRASE).unwrap();
        assert_eq!(plain.as_slice(), b"");
    }

    #[test]
    fn salts_differ_between_encryptions() {
        let a = encrypted();
        let b = encrypted();
        assert_ne!(a[16..48], b[16..48]);
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    }

    #[test]
    fn calibration_respects_minimum_and_maximum_costs() {
        assert_eq!(calibrated_p(2.0), 1);
        assert_eq!(calibrated_p(1.0), 1);
        assert_eq!(calibrated_p(0.25), 4);
        assert_eq!(calibrated_p(0.000001), MAX_P);
    }

    #[test]
    fn short_magic_only_header_is_rejected_without_panicking() {
        assert_eq!(parameters(b"scrypt"), Err(Error::NotScryptFormat));
    }

    #[test]
    fn default_params_are_valid() {
        assert_eq!(validate(&Params::default()), Ok(()));
    }

    #[test]
    fn wrong_passphrase() {
        let data = encrypted();
        assert_eq!(
            decrypt(&data, b"wrong").unwrap_err(),
            Error::WrongPassphrase
        );
    }

    #[test]
    fn bad_magic() {
        let mut data = encrypted();
        data[0] ^= 0x01;
        assert_eq!(
            decrypt(&data, PASSPHRASE).unwrap_err(),
            Error::NotScryptFormat
        );
    }

    #[test]
    fn unsupported_version() {
        let mut data = encrypted();
        data[6] = 1;
        assert_eq!(
            decrypt(&data, PASSPHRASE).unwrap_err(),
            Error::UnsupportedVersion(1)
        );
    }

    #[test]
    fn salt_bit_flip_fails_checksum() {
        let mut data = encrypted();
        data[20] ^= 0x01;
        assert_eq!(
            decrypt(&data, PASSPHRASE).unwrap_err(),
            Error::NotScryptFormat
        );
    }

    #[test]
    fn header_mac_bit_flip() {
        let mut data = encrypted();
        data[70] ^= 0x01;
        assert_eq!(
            decrypt(&data, PASSPHRASE).unwrap_err(),
            Error::WrongPassphrase
        );
    }

    #[test]
    fn body_bit_flip() {
        let mut data = encrypted();
        data[HEADER_LEN] ^= 0x01;
        assert_eq!(decrypt(&data, PASSPHRASE).unwrap_err(), Error::Corrupt);
    }

    #[test]
    fn trailer_bit_flip() {
        let mut data = encrypted();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        assert_eq!(decrypt(&data, PASSPHRASE).unwrap_err(), Error::Corrupt);
    }

    #[test]
    fn truncated_file() {
        let data = encrypted();
        assert_eq!(
            decrypt(&data[..OVERHEAD - 1], PASSPHRASE).unwrap_err(),
            Error::Truncated
        );
        // Cut inside the body: the trailer MAC no longer matches.
        assert_eq!(
            decrypt(&data[..data.len() - 1], PASSPHRASE).unwrap_err(),
            Error::Corrupt
        );
    }

    #[test]
    fn oversized_params_rejected_before_kdf() {
        let mut data = encrypted();
        data[7] = 30; // log2(N) = 30 would need 8 GiB at r=8
        assert_eq!(
            decrypt(&data, PASSPHRASE).unwrap_err(),
            Error::ParamsTooLarge { log_n: 30, r: 8 }
        );
    }

    #[test]
    fn zero_params_rejected() {
        for params in [
            Params {
                log_n: 0,
                r: 8,
                p: 1,
            },
            Params {
                log_n: 12,
                r: 0,
                p: 1,
            },
            Params {
                log_n: 12,
                r: 8,
                p: 0,
            },
        ] {
            assert!(matches!(
                encrypt(PLAINTEXT, PASSPHRASE, &params).unwrap_err(),
                Error::InvalidParams { .. }
            ));
        }
    }
}
