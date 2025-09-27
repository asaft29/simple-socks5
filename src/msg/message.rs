//! SOCKS5 handshake messages (RFC 1928).
//!
//! This module defines the messages exchanged during the initial
//! client–server handshake:
//!
//! - [`VersionMessage`] → sent by the client to advertise supported
//!   authentication methods.
//! - [`MethodSelection`] → sent by the server to choose one method.
//!
//! These are defined in [RFC 1928, section 3](https://www.rfc-editor.org/rfc/rfc1928#section-3).

use super::method::*;
use crate::error::SocksError;

/// Client's version/methods message.
///
/// This message is sent by the client immediately after establishing
/// a TCP connection, and lists the authentication methods it supports.
///
/// ```text
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 1  |    1     | 1 to 255 |
/// +----+----------+----------+
/// ```
///
/// - `VER`: SOCKS version (`0x05`).
/// - `NMETHODS`: number of methods that follow.
/// - `METHODS`: list of supported authentication methods.
///
/// Defined in RFC 1928, section 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMessage {
    /// The SOCKS protocol version (must be `0x05`).
    pub ver: u8,
    /// The list of authentication methods supported by the client.
    pub methods: Vec<Method>,
}

impl VersionMessage {
    /// Creates a new [`VersionMessage`] with the given supported methods.
    ///
    /// # Example
    /// ```
    /// use socks5::message::VersionMessage;
    /// use socks5::method::{FixedMethod, Method};
    ///
    /// let msg = VersionMessage::new(vec![Method::Fixed(FixedMethod::NoAuth)]);
    /// assert_eq!(msg.ver, 0x05);
    /// ```
    pub fn new(methods: Vec<Method>) -> Self {
        Self { ver: 0x05, methods }
    }
}

impl TryFrom<&[u8]> for VersionMessage {
    type Error = SocksError;

    /// Attempts to parse a [`VersionMessage`] from raw bytes.
    ///
    /// Returns an error if:
    /// - the buffer is shorter than 2 bytes
    /// - the version is not `0x05`
    /// - the buffer does not contain the declared number of methods
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(SocksError::VersionMessageTooShort);
        }

        let ver = bytes[0];
        if ver != 0x05 {
            return Err(SocksError::UnsupportedVersion(ver));
        }

        let nmethods = bytes[1] as usize;
        if bytes.len() < 2 + nmethods {
            return Err(SocksError::IncompleteVersionMessage);
        }

        let mut methods = Vec::with_capacity(nmethods);
        for b in &bytes[2..2 + nmethods] {
            methods.push(Method::from_u8(*b)?);
        }

        Ok(Self { ver, methods })
    }
}

/// Server's method selection message.
///
/// This message is sent in response to a [`VersionMessage`],
/// informing the client which authentication method has been chosen.
///
/// ```text
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
///
/// - `VER`: SOCKS version (`0x05`).
/// - `METHOD`: one of the methods proposed by the client, or `0xFF`
///   if none are acceptable.
///
/// Defined in RFC 1928, section 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSelection {
    /// The SOCKS protocol version (must be `0x05`).
    pub ver: u8,
    /// The authentication method selected by the server.
    pub method: Method,
}

impl MethodSelection {
    /// Creates a new [`MethodSelection`] with the given method.
    ///
    /// # Example
    /// ```
    /// use socks5::message::MethodSelection;
    /// use socks5::method::{FixedMethod, Method};
    ///
    /// let sel = MethodSelection::new(Method::Fixed(FixedMethod::NoAuth));
    /// assert_eq!(sel.to_bytes(), [0x05, 0x00]);
    /// ```
    pub fn new(method: Method) -> Self {
        Self { ver: 0x05, method }
    }

    /// Serializes this [`MethodSelection`] into a 2-byte array.
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.ver, self.method.to_u8()]
    }
}

impl TryFrom<&[u8]> for MethodSelection {
    type Error = SocksError;

    /// Attempts to parse a [`MethodSelection`] from raw bytes.
    ///
    /// Returns an error if:
    /// - the buffer is shorter than 2 bytes
    /// - the version is not `0x05`
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(SocksError::VersionMessageTooShort);
        }

        let ver = bytes[0];
        if ver != 0x05 {
            return Err(SocksError::UnsupportedVersion(ver));
        }

        let method = Method::from_u8(bytes[1])?;
        Ok(Self { ver, method })
    }
}
