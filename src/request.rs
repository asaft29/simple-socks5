use crate::ATYP;
use crate::parse::parse_ip_port; // import the helper
use std::net::{Ipv4Addr, Ipv6Addr};

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum CMD {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[derive(Debug)]
pub enum Destination {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Domain(String, u16),
}

#[derive(Debug)]
pub struct Request {
    pub ver: u8, // 0x05
    pub cmd: CMD,
    pub rsv: u8, // 0x00
    pub atyp: ATYP,
    pub dst: Destination,
}
impl Request {
    pub fn from_bytes(buf: &[u8]) -> Option<Request> {
        if buf.len() < 4 {
            return None;
        }

        let ver = buf[0];
        let cmd = match buf[1] {
            0x01 => CMD::Connect,
            0x02 => CMD::Bind,
            0x03 => CMD::UdpAssociate,
            _ => return None,
        };
        let rsv = buf[2];
        let atyp = match buf[3] {
            0x01 => ATYP::V4,
            0x03 => ATYP::DomainName,
            0x04 => ATYP::V6,
            _ => return None,
        };

        let dst = match atyp {
            ATYP::V4 => {
                let (ip_port, _) = parse_ip_port(&buf[4..], 0x01)?;
                if let crate::parse::IpPort::V4(ip, port) = ip_port {
                    Destination::V4(ip, port)
                } else {
                    return None;
                }
            }
            ATYP::V6 => {
                let (ip_port, _) = parse_ip_port(&buf[4..], 0x04)?;
                if let crate::parse::IpPort::V6(ip, port) = ip_port {
                    Destination::V6(ip, port)
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
                Destination::Domain(domain, port)
            }
        };

        Some(Request {
            ver,
            cmd,
            rsv,
            atyp,
            dst,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.push(self.ver);
        buf.push(self.cmd as u8);
        buf.push(self.rsv);
        buf.push(self.atyp as u8);

        match &self.dst {
            Destination::V4(addr, port) => {
                buf.extend_from_slice(&addr.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Destination::V6(addr, port) => {
                buf.extend_from_slice(&addr.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Destination::Domain(name, port) => {
                buf.push(name.len() as u8);
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf
    }
}
