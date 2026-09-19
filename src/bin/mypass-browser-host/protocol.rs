//! Firefox native-messaging wire protocol: each
//! message is a 32-bit length in native byte order followed by that many
//! bytes of UTF-8 JSON.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use mypass::{PasswordEntry, Secret};

/// Cap on an incoming message. Firefox permits browser→host messages up to
/// 4 GiB, but every request this host understands is tiny; a small cap turns
/// a corrupt or hostile length prefix into a clean error instead of a huge
/// allocation.
const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Read one length-prefixed message. `Ok(None)` means a clean EOF (the port
/// was closed — the browser quit, the extension was disabled, or the port was
/// dropped), which is the host's normal shutdown signal.
pub fn read_message(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message length {len} exceeds {MAX_MESSAGE_LEN}"),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one length-prefixed message.
pub fn write_message(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response too large"))?;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

/// A request, parsed leniently: an unknown `type` is still dispatched (and
/// answered with `error/internal`) rather than failing to parse, and the
/// `id` is preserved so the response can echo it.
#[derive(Debug, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub id: u64,
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub origin: Option<String>,
    /// The HTTP-authentication realm the challenge named, on the requests that
    /// answer one. Absent (or `null`) means the challenge carried no realm, or
    /// that this is not an HTTP-authentication request at all; either way only
    /// entries that name no realm are eligible.
    pub realm: Option<String>,
}

/// A single released login on the wire. Deliberately only `name`, `username`
/// and `password` (§6) — the entry's `url` and any other stored fields are not
/// exposed to the browser, which does not need them.
#[derive(Debug, Serialize)]
pub struct Login<'a> {
    pub name: &'a str,
    pub username: &'a str,
    pub password: &'a Secret,
}

impl<'a> From<&'a PasswordEntry> for Login<'a> {
    fn from(entry: &'a PasswordEntry) -> Self {
        Login {
            name: &entry.name,
            username: &entry.username,
            password: &entry.password,
        }
    }
}

/// A response (host → extension). Serialized with a `type` tag matching §6.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Response<'a> {
    Logins {
        id: u64,
        entries: Vec<Login<'a>>,
    },
    Ok {
        id: u64,
    },
    Status {
        id: u64,
        locked: bool,
        version: &'a str,
    },
    Error {
        id: u64,
        code: &'a str,
        message: String,
    },
}

impl Response<'_> {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("response serializes")
    }
}
