use crate::ATYP;
use crate::error::SocksError;
use crate::parse::{AddrPort, Parse};

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum CMD {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[derive(Debug)]
pub struct ConnRequest {
    pub ver: u8, // 0x05
    pub cmd: CMD,
    pub rsv: u8, // 0x00
    pub atyp: ATYP,
    pub dst: AddrPort,
}

impl ConnRequest {
    pub fn new(ver: u8, cmd: CMD, rsv: u8, atyp: ATYP, dst: AddrPort) -> Self {
        Self {
            ver,
            cmd,
            rsv,
            atyp,
            dst,
        }
    }

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

impl TryFrom<&[u8]> for ConnRequest {
    type Error = SocksError;

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
