use crate::ATYP;
use crate::parse::parse_ip_port;
use std::net::{Ipv4Addr, Ipv6Addr};

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

pub enum Bnd {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

pub struct Reply {
    pub ver: u8, // 0x05
    pub rep: Rep,
    pub rsv: u8, // 0x00
    pub atyp: ATYP,
    pub bnd: Bnd,
}

impl Reply {
    pub fn from_bytes(buf: &[u8]) -> Option<Reply> {
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
                let (ip_port, _) = parse_ip_port(&buf[4..], 0x01)?;
                if let crate::parse::IpPort::V4(ip, port) = ip_port {
                    Bnd::V4(ip, port)
                } else {
                    return None;
                }
            }
            ATYP::V6 => {
                let (ip_port, _) = parse_ip_port(&buf[4..], 0x04)?;
                if let crate::parse::IpPort::V6(ip, port) = ip_port {
                    Bnd::V6(ip, port)
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
                Bnd::Domain(domain, port)
            }
        };

        Some(Reply {
            ver,
            rep,
            rsv,
            atyp,
            bnd,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.push(self.ver);
        buf.push(self.rep as u8);
        buf.push(self.rsv);
        buf.push(self.atyp as u8);

        match &self.bnd {
            Bnd::V4(addr, port) => {
                buf.extend_from_slice(&addr.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Bnd::V6(addr, port) => {
                buf.extend_from_slice(&addr.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Bnd::Domain(name, port) => {
                buf.push(name.len() as u8);
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf
    }
}
