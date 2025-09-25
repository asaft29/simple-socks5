use crate::error::SocksError;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FixedMethod {
    NoAuth = 0x00,
    GssApi = 0x01,
    UsePass = 0x02,
    NoAcceptable = 0xFF,
}

/// Represents any SOCKS5 method, including fixed, IANA-assigned, and private ranges.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Method {
    Fixed(FixedMethod),
    IanaAssigned(u8),
    Private(u8),
}

impl FixedMethod {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

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
    pub fn to_u8(self) -> u8 {
        match self {
            Method::Fixed(f) => f.to_u8(),
            Method::IanaAssigned(b) => b,
            Method::Private(b) => b,
        }
    }

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
