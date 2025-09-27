//! Authentication reply message for SOCKS5 username/password authentication.
//!
//! Defined in [RFC 1929, section 2](https://www.rfc-editor.org/rfc/rfc1929#section-2).
//!
//! After a client sends an authentication request, the server replies with
//! a 2–byte message:
//!
//! ```text
//! +----+--------+
//! |VER | STATUS |
//! +----+--------+
//! |  1 |   1    |
//! +----+--------+
//!
//! o VER    - the version of the subnegotiation (always 0x01)
//! o STATUS - 0x00 for success, any non-zero value indicates failure
//! ```
//!
//! If the status is non-zero, the client MUST close the connection.

use crate::error::SocksError;

/// Represents the status of the authentication, as per RFC 1929.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthStatus {
    /// Authentication succeeded (`STATUS = 0x00`).
    Success = 0x00,
    /// Authentication failed (any non-zero `STATUS`).
    Failure = 0x01,
}

/// Represents an authentication reply sent by the server.
pub struct AuthReply {
    /// Authentication protocol version (`VER`), always `0x01` (RFC 1929 §2).
    pub ver: u8,
    /// The status of the authentication (`STATUS`).
    pub status: AuthStatus,
}

impl AuthReply {
    /// Creates a new `AuthReply` with the given status.
    ///
    /// # Arguments
    ///
    /// * `status` - Authentication outcome (success or failure).
    pub fn new(status: AuthStatus) -> Self {
        Self { ver: 0x01, status }
    }

    /// Converts the `AuthReply` into its 2–byte wire format.
    ///
    /// Layout: `[VER, STATUS]`.
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.status as u8]
    }
}

impl TryFrom<&[u8]> for AuthReply {
    type Error = SocksError;

    /// Parses an authentication reply from a 2–byte buffer.
    ///
    /// # Errors
    /// - [`SocksError::AuthMessageTooShort`] if the slice is not 2 bytes long.
    /// - [`SocksError::UnsupportedAuthVersion`] if `VER != 0x01`.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 2 {
            return Err(SocksError::AuthMessageTooShort);
        }

        let ver = bytes[0];
        if ver != 0x01 {
            return Err(SocksError::UnsupportedAuthVersion(ver));
        }

        let status = match bytes[1] {
            0x00 => AuthStatus::Success,
            _ => AuthStatus::Failure,
        };

        Ok(Self { ver, status })
    }
}

