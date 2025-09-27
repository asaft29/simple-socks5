//! SOCKS5 client connection request (RFC 1928 §4).
//!
//! After negotiation, the client sends a request message:
//!
//! ```text
//! +----+-----+-------+------+----------+----------+
//! |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//! +----+-----+-------+------+----------+----------+
//! | 1  |  1  | X'00' |  1   | Variable |    2     |
//! +----+-----+-------+------+----------+----------+
//!
//! o VER      - protocol version: X'05'
//! o CMD      - command code:
//!                0x01 = CONNECT
//!                0x02 = BIND
//!                0x03 = UDP ASSOCIATE
//! o RSV      - reserved, must be 0x00
//! o ATYP     - address type of DST.ADDR
//!                0x01 = IPv4 address
//!                0x03 = Domain name
//!                0x04 = IPv6 address
//! o DST.ADDR - destination address
//! o DST.PORT - destination port in network byte order
//! ```

use crate::ATYP;
use crate::error::SocksError;
use crate::parse::{AddrPort, Parse};
use std::fmt;

/// The command (`CMD`) of a SOCKS5 request (RFC 1928 §4).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CMD {
    /// CONNECT command (0x01): establishes a TCP connection to the target host.
    Connect = 0x01,
    /// BIND command (0x02): used for inbound connections (rarely implemented).
    Bind = 0x02,
    /// UDP ASSOCIATE command (0x03): establishes a UDP relay.
    UdpAssociate = 0x03,
}

impl fmt::Display for CMD {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CMD::Connect => write!(f, "CONNECT"),
            CMD::Bind => write!(f, "BIND"),
            CMD::UdpAssociate => write!(f, "UDP_ASSOCIATE"),
        }
    }
}

/// Represents a SOCKS5 connection request (RFC 1928 §4).
#[derive(Debug)]
pub struct ConnRequest {
    /// Protocol version (`VER`), must be 0x05.
    pub ver: u8,
    /// Command (`CMD`): CONNECT, BIND, or UDP ASSOCIATE.
    pub cmd: CMD,
    /// Reserved byte (`RSV`), must be 0x00.
    pub rsv: u8,
    /// Address type (`ATYP`): IPv4, IPv6, or domain name.
    pub atyp: ATYP,
    /// Destination address and port (`DST.ADDR`, `DST.PORT`).
    pub dst: AddrPort,
}

impl ConnRequest {
    /// Creates a new `ConnRequest`.
    pub fn new(ver: u8, cmd: CMD, rsv: u8, atyp: ATYP, dst: AddrPort) -> Self {
        Self {
            ver,
            cmd,
            rsv,
            atyp,
            dst,
        }
    }

    /// Serializes the request into the SOCKS5 wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![self.ver, self.cmd as u8, self.rsv, self.atyp as u8];

        match &self.dst {
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

impl fmt::Display for ConnRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SOCKS5 Request {{")?;
        writeln!(f, "  CMD : {}", self.cmd)?;
        writeln!(f, "  ATYP: {}", self.atyp)?;
        writeln!(f, "  DST : {}", self.dst)?;
        writeln!(f, "  VER : {}", self.ver)?;
        writeln!(f, "  RSV : {}", self.rsv)?;
        write!(f, "}}")
    }
}

impl TryFrom<&[u8]> for ConnRequest {
    type Error = SocksError;

    /// Parses a SOCKS5 connection request from raw bytes.
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err(SocksError::ConnRequestTooShort);
        }

        let ver = buf[0];

        let cmd = match buf[1] {
            0x01 => CMD::Connect,
            0x02 => CMD::Bind,
            0x03 => CMD::UdpAssociate,
            other => return Err(SocksError::UnsupportedCommand(other)),
        };

        let rsv = buf[2];

        let atyp = match buf[3] {
            0x01 => ATYP::V4,
            0x03 => ATYP::DomainName,
            0x04 => ATYP::V6,
            other => return Err(SocksError::InvalidAddressType(other)),
        };

        let dst = match atyp {
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

        Ok(ConnRequest {
            ver,
            cmd,
            rsv,
            atyp,
            dst,
        })
    }
}
