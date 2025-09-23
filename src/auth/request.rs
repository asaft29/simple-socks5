use anyhow::{Result, anyhow};

const VER: u8 = 0x01;

pub struct AuthRequest {
    pub ver: u8,
    pub uname: String,
    pub passwd: String,
}

impl TryFrom<&[u8]> for AuthRequest {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(anyhow!("AuthRequest too short"));
        }

        let ver = bytes[0];
        if ver != VER {
            return Err(anyhow!("Unsupported auth version: {ver}"));
        }

        let ulen = bytes[1] as usize;
        if bytes.len() < 2 + ulen + 1 {
            return Err(anyhow!("AuthRequest truncated before username"));
        }

        let uname = String::from_utf8(bytes[2..2 + ulen].to_vec())
            .map_err(|_| anyhow!("Invalid UTF-8 in username"))?;

        let plen_index = 2 + ulen;
        let plen = bytes[plen_index] as usize;

        if bytes.len() < plen_index + 1 + plen {
            return Err(anyhow!("AuthRequest truncated before password"));
        }

        let passwd = String::from_utf8(bytes[plen_index + 1..plen_index + 1 + plen].to_vec())
            .map_err(|_| anyhow!("Invalid UTF-8 in password"))?;

        Ok(Self { ver, uname, passwd })
    }
}
