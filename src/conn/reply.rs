use crate::ATYP;
use crate::error::SocksError;
use crate::parse::{AddrPort, Parse};

/// Represents the reply from the SOCKS5 server.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Rep {
    /// Represents a successful connection.
    Succeeded = 0x00,
    /// Represents a general failure.
    GeneralFailure = 0x01,
    /// Represents a connection that is not allowed.
    ConnectionNotAllowed = 0x02,
    /// Represents a network that is unreachable.
    NetworkUnreachable = 0x03,
    /// Represents a host that is unreachable.
    HostUnreachable = 0x04,
    /// Represents a connection that was refused.
    ConnectionRefused = 0x05,
    /// Represents a TTL that has expired.
    TTLExpired = 0x06,
    /// Represents a command that is not supported.
    CommandNotSupported = 0x07,
    /// Represents an address type that is not supported.
    AddressTypeNotSupported = 0x08,
}

/// Represents a connection reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnReply {
    /// The SOCKS5 protocol version.
    pub ver: u8, // 0x05
    /// The reply from the server.
    pub rep: Rep,
    /// The reserved byte.
    pub rsv: u8, // 0x00
    /// The address type.
    pub atyp: ATYP,
    /// The bound address and port.
    pub bnd: AddrPort,
}

impl ConnReply {
    /// Creates a new `ConnReply`.
    ///
    /// # Arguments
    ///
    /// * `ver` - The SOCKS5 protocol version.
    /// * `rep` - The reply from the server.
    /// * `rsv` - The reserved byte.
    /// * `atyp` - The address type.
    /// * `bnd` - The bound address and port.
    pub fn new(ver: u8, rep: Rep, rsv: u8, atyp: ATYP, bnd: AddrPort) -> Self {
        Self {
            ver,
            rep,
            rsv,
            atyp,
            bnd,
        }
    }

    /// Converts the `ConnReply` to a byte array.
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

    /// Converts a byte slice to a `ConnReply`.
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