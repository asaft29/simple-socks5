//! SOCKS5 server connection reply (RFC 1928 §6).
//!
//! After processing a request, the server replies with:
//!
//! ```text
//! +----+-----+-------+------+----------+----------+
//! |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//! +----+-----+-------+------+----------+----------+
//! | 1  |  1  | X'00' |  1   | Variable |    2     |
//! +----+-----+-------+------+----------+----------+
//!
//! o VER       - protocol version: X'05'
//! o REP       - reply field, see below
//! o RSV       - reserved, must be 0x00
//! o ATYP      - address type of BND.ADDR
//! o BND.ADDR  - server bound address
//! o BND.PORT  - server bound port in network byte order
//!
//! The BND fields are meaningful in BIND/UDP_ASSOCIATE, but may be ignored in CONNECT.
//! ```

use crate::ATYP;
use crate::error::SocksError;
use crate::parse::{AddrPort, Parse};

/// Reply codes (`REP`) for SOCKS5 connection replies (RFC 1928 §6).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Rep {
    /// 0x00 - Succeeded
    Succeeded = 0x00,
    /// 0x01 - General SOCKS server failure
    GeneralFailure = 0x01,
    /// 0x02 - Connection not allowed by ruleset
    ConnectionNotAllowed = 0x02,
    /// 0x03 - Network unreachable
    NetworkUnreachable = 0x03,
    /// 0x04 - Host unreachable
    HostUnreachable = 0x04,
    /// 0x05 - Connection refused by destination host
    ConnectionRefused = 0x05,
    /// 0x06 - TTL expired
    TTLExpired = 0x06,
    /// 0x07 - Command not supported
    CommandNotSupported = 0x07,
    /// 0x08 - Address type not supported
    AddressTypeNotSupported = 0x08,
}

/// Represents a SOCKS5 server reply (RFC 1928 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnReply {
    /// Protocol version (`VER`), must be 0x05.
    pub ver: u8,
    /// Reply field (`REP`): success or error status.
    pub rep: Rep,
    /// Reserved byte (`RSV`), must be 0x00.
    pub rsv: u8,
    /// Address type (`ATYP`).
    pub atyp: ATYP,
    /// Bound address and port (`BND.ADDR`, `BND.PORT`).
    pub bnd: AddrPort,
}

impl ConnReply {
    /// Creates a new `ConnReply`.
    pub fn new(ver: u8, rep: Rep, rsv: u8, atyp: ATYP, bnd: AddrPort) -> Self {
        Self {
            ver,
            rep,
            rsv,
            atyp,
            bnd,
        }
    }

    /// Serializes the reply into the SOCKS5 wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.ver, self.rep as u8, self.rsv, self.atyp as u8];

        match &self.bnd {
            AddrPort::V4(addr, port) => {
                buf.extend_from_slice(&addr.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            AddrPort::V6(addr, port) => {
                buf.extend_from_slice(&addr.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            AddrPort::Domain(name, port) => {
                buf.push(name.len() as u8);
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf
    }
}

impl TryFrom<&[u8]> for ConnReply {
    type Error = SocksError;

    /// Parses a SOCKS5 connection reply from raw bytes.
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err(SocksError::ReplyTooShort);
        }

        let ver = buf[0];

        let rep = match buf[1] {
            0x00 => Rep::Succeeded,
            0x01 => Rep::GeneralFailure,
            0x02 => Rep::ConnectionNotAllowed,
            0x03 => Rep::NetworkUnreachable,
            0x04 => Rep::HostUnreachable,
            0x05 => Rep::ConnectionRefused,
            0x06 => Rep::TTLExpired,
            0x07 => Rep::CommandNotSupported,
            0x08 => Rep::AddressTypeNotSupported,
            _ => return Err(SocksError::ConnRequestTooShort),
        };

        let rsv = buf[2];

        let atyp = match buf[3] {
            0x01 => ATYP::V4,
            0x03 => ATYP::DomainName,
            0x04 => ATYP::V6,
            other => return Err(SocksError::InvalidAddressType(other)),
        };

        let bnd = match atyp {
            ATYP::V4 => {
                let (ip_port, _) =
                    Parse::parse_ip_port(&buf[4..], 0x01).ok_or(SocksError::ConnRequestTooShort)?;
                if let AddrPort::V4(ip, port) = ip_port {
                    AddrPort::V4(ip, port)
                } else {
                    return Err(SocksError::InvalidAddressType(0x01));
                }
            }
            ATYP::V6 => {
                let (ip_port, _) =
                    Parse::parse_ip_port(&buf[4..], 0x04).ok_or(SocksError::ConnRequestTooShort)?;
                if let AddrPort::V6(ip, port) = ip_port {
                    AddrPort::V6(ip, port)
                } else {
                    return Err(SocksError::InvalidAddressType(0x04));
                }
            }
            ATYP::DomainName => {
                let len = buf[4] as usize;
                if buf.len() < 5 + len + 2 {
                    return Err(SocksError::InvalidDomain);
                }
                let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
                AddrPort::Domain(domain, port)
            }
        };

        Ok(ConnReply {
            ver,
            rep,
            rsv,
            atyp,
            bnd,
        })
    }
}

