//! SOCKS5 address and port parsing utilities.
//!
//! This module defines [`AddrPort`], a representation of a destination
//! address and port (IPv4, IPv6, or domain), and [`Parse`], a helper for
//! decoding such addresses from raw SOCKS5 protocol bytes.
//!
//! The address formats are defined in
//! [RFC 1928 §5, "Addressing"](<https://www.rfc-editor.org/rfc/rfc1928#section-5>).
//!
//! Example usage:
//! ```rust
//! use simple_socks5::parse::{AddrPort, Parse};
//!
//! // Example: IPv4 address 127.0.0.1:8080
//! let buf = [127, 0, 0, 1, 0x1F, 0x90]; // 127.0.0.1:8080
//! let (addr, used) = Parse::parse_ip_port(&buf, 0x01).unwrap();
//! assert_eq!(addr.to_string(), "127.0.0.1:8080");
//! assert_eq!(used, 6);
//! ```

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Represents a destination address and port.
///
/// SOCKS5 requests and replies contain an address field that may be:
/// - An IPv4 address (`ATYP = 0x01`).
/// - An IPv6 address (`ATYP = 0x04`).
/// - A domain name (`ATYP = 0x03`), which is represented here as [`AddrPort::Domain`].
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum AddrPort {
    /// An IPv4 address and port.
    V4(Ipv4Addr, u16),

    /// An IPv6 address and port.
    V6(Ipv6Addr, u16),

    /// A domain name and port.
    Domain(String, u16),
}

impl fmt::Display for AddrPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrPort::V4(ip, port) => write!(f, "{}:{}", ip, port),
            AddrPort::V6(ip, port) => write!(f, "[{}]:{}", ip, port),
            AddrPort::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

/// Provides parsing utilities for extracting addresses from raw bytes.
pub struct Parse;

impl Parse {
    /// Parses an IP address and port from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `buf` - The byte slice containing the raw address data.
    /// * `atyp` - The address type byte (`ATYP`) as defined by RFC 1928:
    ///   - `0x01`: IPv4 address (4 bytes) + port (2 bytes).
    ///   - `0x04`: IPv6 address (16 bytes) + port (2 bytes).
    ///
    /// # Returns
    ///
    /// Returns `Some((AddrPort, used_bytes))` on success, where `used_bytes` is the
    /// number of bytes consumed. Returns `None` if the buffer is too short or if
    /// the `atyp` is unsupported (e.g., domain names are not handled here).
    pub fn parse_ip_port(buf: &[u8], atyp: u8) -> Option<(AddrPort, usize)> {
        match atyp {
            0x01 => {
                // IPv4
                if buf.len() < 6 {
                    return None;
                }
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Some((AddrPort::V4(ip, port), 6))
            }
            0x04 => {
                // IPv6
                if buf.len() < 18 {
                    return None;
                }
                let ip = Ipv6Addr::new(
                    ((buf[0] as u16) << 8) | buf[1] as u16,
                    ((buf[2] as u16) << 8) | buf[3] as u16,
                    ((buf[4] as u16) << 8) | buf[5] as u16,
                    ((buf[6] as u16) << 8) | buf[7] as u16,
                    ((buf[8] as u16) << 8) | buf[9] as u16,
                    ((buf[10] as u16) << 8) | buf[11] as u16,
                    ((buf[12] as u16) << 8) | buf[13] as u16,
                    ((buf[14] as u16) << 8) | buf[15] as u16,
                );
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                Some((AddrPort::V6(ip, port), 18))
            }
            _ => None,
        }
    }
}
