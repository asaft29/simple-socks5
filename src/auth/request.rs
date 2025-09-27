//! Authentication request message for SOCKS5 username/password authentication.
//!
//! Defined in [RFC 1929, section 2](https://www.rfc-editor.org/rfc/rfc1929#section-2).
//!
//! After selecting username/password authentication during method negotiation
//! ([RFC 1928, section 3](https://www.rfc-editor.org/rfc/rfc1928#section-3)),
//! the client sends a request of the form:
//!
//! ```text
//! +----+------+----------+------+----------+
//! |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//! +----+------+----------+------+----------+
//! |  1 |  1   | 1–255    |  1   | 1–255    |
//! +----+------+----------+------+----------+
//!
//! o VER     - subnegotiation version (always 0x01)
//! o ULEN    - length of username in bytes
//! o UNAME   - username (1–255 bytes)
//! o PLEN    - length of password in bytes
//! o PASSWD  - password (1–255 bytes)
//! ```

use crate::error::SocksError;

/// Represents an authentication request from a client (RFC 1929 §2).
pub struct AuthRequest {
    /// Authentication protocol version (`VER`), always `0x01`.
    pub ver: u8,
    /// The username (`UNAME`).
    pub uname: String,
    /// The password (`PASSWD`).
    pub passwd: String,
}

impl AuthRequest {
    /// Creates a new `AuthRequest`.
    ///
    /// # Arguments
    ///
    /// * `uname` - Username for authentication.
    /// * `passwd` - Password for authentication.
    pub fn new(uname: String, passwd: String) -> Self {
        Self {
            ver: 0x01,
            uname,
            passwd,
        }
    }
}

impl TryFrom<&[u8]> for AuthRequest {
    type Error = SocksError;

    /// Parses an authentication request from raw bytes.
    ///
    /// # Errors
    /// - [`SocksError::AuthMessageTooShort`] if the message is shorter than 2 bytes.
    /// - [`SocksError::UnsupportedAuthVersion`] if `VER != 0x01`.
    /// - [`SocksError::AuthFailed`] if the username or password are invalid UTF-8,
    ///   or the buffer is truncated before expected fields.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(SocksError::AuthMessageTooShort);
        }

        let ver = bytes[0];
        if ver != 0x01 {
            return Err(SocksError::UnsupportedAuthVersion(ver));
        }

        let ulen = bytes[1] as usize;
        if bytes.len() < 2 + ulen + 1 {
            return Err(SocksError::AuthFailed("truncated before username".into()));
        }

        let uname = String::from_utf8(bytes[2..2 + ulen].to_vec())
            .map_err(|_| SocksError::AuthFailed("invalid UTF-8 in username".into()))?;

        let plen_index = 2 + ulen;
        let plen = bytes[plen_index] as usize;

        if bytes.len() < plen_index + 1 + plen {
            return Err(SocksError::AuthFailed("truncated before password".into()));
        }

        let passwd = String::from_utf8(bytes[plen_index + 1..plen_index + 1 + plen].to_vec())
            .map_err(|_| SocksError::AuthFailed("invalid UTF-8 in password".into()))?;

        Ok(Self { ver, uname, passwd })
    }
}
