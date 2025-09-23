use crate::ATYP;
use crate::parse::{AddrPort, Parse};
use anyhow::anyhow;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Rep {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnReply {
    pub ver: u8, // 0x05
    pub rep: Rep,
    pub rsv: u8, // 0x00
    pub atyp: ATYP,
    pub bnd: AddrPort,
}

impl ConnReply {
    pub fn new(ver: u8, rep: Rep, rsv: u8, atyp: ATYP, bnd: AddrPort) -> Self {
        Self {
            ver,
            rep,
            rsv,
            atyp,
            bnd,
        }
    }
    pub fn from_bytes(buf: &[u8]) -> Option<ConnReply> {
        if buf.len() < 4 {
            return None;
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
            _ => return None,
        };

        let rsv = buf[2];

        let atyp = match buf[3] {
            0x01 => ATYP::V4,
            0x03 => ATYP::DomainName,
            0x04 => ATYP::V6,
            _ => return None,
        };

        let bnd = match atyp {
            ATYP::V4 => {
                let (ip_port, _) = Parse::parse_ip_port(&buf[4..], 0x01)?;
                if let crate::parse::AddrPort::V4(ip, port) = ip_port {
                    AddrPort::V4(ip, port)
                } else {
                    return None;
                }
            }
            ATYP::V6 => {
                let (ip_port, _) = Parse::parse_ip_port(&buf[4..], 0x04)?;
                if let crate::parse::AddrPort::V6(ip, port) = ip_port {
                    AddrPort::V6(ip, port)
                } else {
                    return None;
                }
            }
            ATYP::DomainName => {
                let len = buf[4] as usize;
                if buf.len() < 5 + len + 2 {
                    return None;
                }
                let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
                AddrPort::Domain(domain, port)
            }
        };

        Some(ConnReply {
            ver,
            rep,
            rsv,
            atyp,
            bnd,
        })
    }

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
    type Error = anyhow::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 4 {
            return Err(anyhow!(
                "Initial lenght cannot be smaller than 4 : {:?}",
                buf
            ));
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
            _ => return Err(anyhow!("Invalid value for REP : {}", &buf[1])),
        };

        let rsv = buf[2];

        let atyp = match buf[3] {
            0x01 => ATYP::V4,
            0x03 => ATYP::DomainName,
            0x04 => ATYP::V6,
            _ => return Err(anyhow!("Invalid value for ATYP : {}", &buf[3])),
        };

        let bnd = match atyp {
            ATYP::V4 => {
                let (ip_port, _) = Parse::parse_ip_port(&buf[4..], 0x01)
                    .ok_or_else(|| anyhow!("Cannot parse input : {:?}", &buf[4..]))?;
                if let crate::parse::AddrPort::V4(ip, port) = ip_port {
                    AddrPort::V4(ip, port)
                } else {
                    return Err(anyhow!("Invalid V4 : {:?}", ip_port));
                }
            }
            ATYP::V6 => {
                let (ip_port, _) = Parse::parse_ip_port(&buf[4..], 0x04)
                    .ok_or_else(|| anyhow!("Cannot parse input : {:?}", &buf[4..]))?;
                if let crate::parse::AddrPort::V6(ip, port) = ip_port {
                    AddrPort::V6(ip, port)
                } else {
                    return Err(anyhow!("Invalid V6 : {:?}", ip_port));
                }
            }
            ATYP::DomainName => {
                let len = buf[4] as usize;
                if buf.len() < 5 + len + 2 {
                    return Err(anyhow!("Size for DomainName is too short : {}", buf.len()));
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
