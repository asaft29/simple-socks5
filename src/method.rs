// method.rs
use anyhow::{Result, anyhow};

/// Trait to convert to and from u8
pub(crate) trait ToFromU8: Sized {
    fn to_u8(self) -> u8;
    fn from_u8(byte: u8) -> Result<Self>;
}

/// Represents the fixed SOCKS5 authentication methods.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FixedMethod {
    NoAuth = 0x00,
    GssApi = 0x01,
    UsePass = 0x02,
    NoAcceptable = 0xFF,
}

impl std::fmt::Display for FixedMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            FixedMethod::NoAuth => "NO AUTHENTICATION REQUIRED",
            FixedMethod::GssApi => "GSSAPI",
            FixedMethod::UsePass => "USERNAME/PASSWORD",
            FixedMethod::NoAcceptable => "NO ACCEPTABLE METHODS",
        };
        write!(f, "{}", msg)
    }
}

/// Represents any SOCKS5 method, including fixed, IANA-assigned, and private ranges.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub(crate) enum Method {
    Fixed(FixedMethod),
    IanaAssigned(u8),
    Private(u8),
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Fixed(fm) => write!(f, "{}", fm),
            Method::IanaAssigned(b) => write!(f, "IANA ASSIGNED METHOD 0x{:02X}", b),
            Method::Private(b) => write!(f, "PRIVATE METHOD 0x{:02X}", b),
        }
    }
}

impl ToFromU8 for FixedMethod {
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(FixedMethod::NoAuth),
            0x01 => Ok(FixedMethod::GssApi),
            0x02 => Ok(FixedMethod::UsePass),
            0xFF => Ok(FixedMethod::NoAcceptable),
            _ => Err(anyhow!(
                "Value doesn't match with anything : 0x{:02X}",
                byte
            )),
        }
    }
}

impl ToFromU8 for Method {
    fn to_u8(self) -> u8 {
        match self {
            Method::Fixed(f) => f.to_u8(),
            Method::IanaAssigned(b) => b,
            Method::Private(b) => b,
        }
    }

    fn from_u8(byte: u8) -> Result<Self> {
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
