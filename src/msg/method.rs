//! SOCKS5 authentication methods (RFC 1928).
//!
//! This module defines the authentication method identifiers
//! used in the version negotiation phase of the SOCKS5 protocol.
//!
//! - [`FixedMethod`] → reserved values defined in the specification
//! - [`Method`] → general representation, including fixed,
//!   IANA-assigned, and private methods
//!
//! See [RFC 1928, section 3](https://www.rfc-editor.org/rfc/rfc1928#section-3).

use crate::error::SocksError;

/// Fixed authentication methods defined in the SOCKS5 specification.
///
/// These values are reserved and have well-defined meanings.
///
/// ```text
/// 0x00 → No authentication required
/// 0x01 → GSS-API authentication
/// 0x02 → Username/password authentication
/// 0xFF → No acceptable methods
/// ```
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FixedMethod {
    /// No authentication required (`0x00`).
    NoAuth = 0x00,
    /// GSS-API authentication (`0x01`).
    GssApi = 0x01,
    /// Username/password authentication (`0x02`).
    UsePass = 0x02,
    /// No acceptable methods (`0xFF`).
    NoAcceptable = 0xFF,
}

/// Represents any SOCKS5 authentication method.
///
/// This includes:
/// - [`FixedMethod`] values
/// - IANA-assigned methods (`0x03`–`0x7F`)
/// - Private methods (`0x80`–`0xFE`)
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Method {
    /// A fixed, reserved method defined in the specification.
    Fixed(FixedMethod),
    /// An IANA-assigned method (`0x03`–`0x7F`).
    IanaAssigned(u8),
    /// A private-use method (`0x80`–`0xFE`).
    Private(u8),
}

impl FixedMethod {
    /// Converts a [`FixedMethod`] into its byte representation.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Attempts to parse a [`FixedMethod`] from a byte.
    ///
    /// Returns an error if the byte does not correspond
    /// to a reserved value.
    pub fn try_from_u8(byte: u8) -> Result<Self, SocksError> {
        match byte {
            0x00 => Ok(FixedMethod::NoAuth),
            0x01 => Ok(FixedMethod::GssApi),
            0x02 => Ok(FixedMethod::UsePass),
            0xFF => Ok(FixedMethod::NoAcceptable),
            _ => Err(SocksError::UnknownMethod(byte)),
        }
    }
}

impl Method {
    /// Converts a [`Method`] into its byte representation.
    pub fn to_u8(self) -> u8 {
        match self {
            Method::Fixed(f) => f.to_u8(),
            Method::IanaAssigned(b) => b,
            Method::Private(b) => b,
        }
    }

    /// Attempts to parse a [`Method`] from a byte.
    ///
    /// Recognizes:
    /// - `0x00`, `0x01`, `0x02`, `0xFF` → [`FixedMethod`]
    /// - `0x03`–`0x7F` → [`Method::IanaAssigned`]
    /// - `0x80`–`0xFE` → [`Method::Private`]
    pub fn from_u8(byte: u8) -> Result<Self, SocksError> {
        match byte {
            0x00 => Ok(Method::Fixed(FixedMethod::NoAuth)),
            0x01 => Ok(Method::Fixed(FixedMethod::GssApi)),
            0x02 => Ok(Method::Fixed(FixedMethod::UsePass)),
            0xFF => Ok(Method::Fixed(FixedMethod::NoAcceptable)),
            0x03..=0x7F => Ok(Method::IanaAssigned(byte)),
            0x80..=0xFE => Ok(Method::Private(byte)),
        }
    }
}
