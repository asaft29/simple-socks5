use crate::VER;
use crate::error::SocksError;

pub struct AuthRequest {
    pub ver: u8,
    pub uname: String,
    pub passwd: String,
}

impl TryFrom<&[u8]> for AuthRequest {
    type Error = SocksError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(SocksError::AuthMessageTooShort);
        }

        let ver = bytes[0];
        if ver != VER {
            return Err(SocksError::UnsupportedAuthVersion(ver));
        }

        let ulen = bytes[1] as usize;
        if bytes.len() < 2 + ulen + 1 {
            return Err(SocksError::AuthFailed("truncated before username".into()));
        }

        let uname = String::from_utf8(bytes[2..2 + ulen].to_vec())
            .map_err(|_| SocksError::AuthFailed("invalid UTF-8 in username".into()))?;

        let plen_index = 2 + ulen;
        let plen = bytes[plen_index] as usize;

        if bytes.len() < plen_index + 1 + plen {
            return Err(SocksError::AuthFailed("truncated before password".into()));
        }

        let passwd = String::from_utf8(bytes[plen_index + 1..plen_index + 1 + plen].to_vec())
            .map_err(|_| SocksError::AuthFailed("invalid UTF-8 in password".into()))?;

        Ok(Self { ver, uname, passwd })
    }
}
