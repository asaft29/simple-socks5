use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub mod auth;
pub mod conn;
pub mod error;
pub mod msg;
pub mod parse;

use auth::reply::*;
use auth::request::*;
use conn::reply::*;
use conn::request::*;
use msg::message::*;
use msg::method::*;
use parse::AddrPort;

use crate::error::SocksError;

/// Represents an IPv4 address.
pub type V4 = Ipv4Addr;
/// Represents an IPv6 address.
pub type V6 = Ipv6Addr;

/// The SOCKS5 protocol version.
const VER5: u8 = 0x05;
/// The reserved byte, must be 0x00.
const RSV: u8 = 0x00;
/// The authentication version.
const VER: u8 = 0x01;

type UserPassValidator = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Represents the address type.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ATYP {
    /// Represents an IPv4 address.
    V4 = 0x01,
    /// Represents a domain name.
    DomainName = 0x03,
    /// Represents an IPv6 address.
    V6 = 0x04,
}

pub struct Socks5 {
    listener: TcpListener,
    allow_no_auth: bool,
    userpass_validator: Option<UserPassValidator>,
}

impl Socks5 {
    /// Bind a new SOCKS5 server to an address
    pub async fn bind(addr: &str) -> Result<Self, SocksError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            allow_no_auth: false,
            userpass_validator: None,
        })
    }

    /// Enable `NO AUTH` method
    pub fn allow_no_auth(&mut self) {
        self.allow_no_auth = true;
    }

    /// Enable `USERNAME/PASSWORD` method with validator closure
    pub fn allow_userpass<F>(&mut self, validator: F)
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.userpass_validator = Some(Box::new(validator));
    }

    /// Accept a client connection
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), SocksError> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((stream, addr))
    }

    /// Get the local address
    pub fn local_addr(&self) -> Result<SocketAddr, SocksError> {
        Ok(self.listener.local_addr()?)
    }

    // --- Protocol helpers ---

    pub async fn read_version_message(
        stream: &mut TcpStream,
    ) -> Result<VersionMessage, SocksError> {
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        VersionMessage::try_from(&buf[..n])
    }

    pub async fn send_method_selection(
        stream: &mut TcpStream,
        method: Method,
    ) -> Result<(), SocksError> {
        let sel = MethodSelection::new(method);
        stream.write_all(&sel.to_bytes()).await?;
        Ok(())
    }

    pub async fn read_auth_request(stream: &mut TcpStream) -> Result<AuthRequest, SocksError> {
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        AuthRequest::try_from(&buf[..n])
    }

    pub async fn send_auth_reply(
        stream: &mut TcpStream,
        status: AuthStatus,
    ) -> Result<(), SocksError> {
        let reply = AuthReply::new(status);
        stream.write_all(&reply.to_bytes()).await?;
        Ok(())
    }

    pub async fn read_conn_request(stream: &mut TcpStream) -> Result<ConnRequest, SocksError> {
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        ConnRequest::try_from(&buf[..n])
    }

    pub async fn send_conn_reply(
        stream: &mut TcpStream,
        rep: Rep,
        atyp: ATYP,
        addr: AddrPort,
    ) -> Result<(), SocksError> {
        let reply = ConnReply::new(0x05, rep, 0x00, atyp, addr);
        stream.write_all(&reply.to_bytes()).await?;
        Ok(())
    }

    /// Create a UDP socket for `UDP ASSOCIATE`
    pub async fn bind_udp(addr: &str) -> Result<UdpSocket, SocksError> {
        let sock = UdpSocket::bind(addr).await?;
        Ok(sock)
    }

    /// Perform authentication according to configured methods
    pub async fn authenticate(&self, stream: &mut TcpStream) -> Result<(), SocksError> {
        let version_msg = Self::read_version_message(stream).await?;

        let mut selected = Method::Fixed(FixedMethod::NoAcceptable);

        if self.allow_no_auth
            && version_msg
                .methods
                .contains(&Method::Fixed(FixedMethod::NoAuth))
        {
            selected = Method::Fixed(FixedMethod::NoAuth);
        } else if self.userpass_validator.is_some()
            && version_msg
                .methods
                .contains(&Method::Fixed(FixedMethod::UsePass))
        {
            selected = Method::Fixed(FixedMethod::UsePass);
        }

        Self::send_method_selection(stream, selected).await?;

        match selected {
            Method::Fixed(FixedMethod::NoAuth) => Ok(()),

            Method::Fixed(FixedMethod::UsePass) => {
                let auth_req = Self::read_auth_request(stream).await?;
                let validator = self.userpass_validator.as_ref().unwrap();

                if validator(&auth_req.uname, &auth_req.passwd) {
                    Self::send_auth_reply(stream, AuthStatus::Success).await?;
                    Ok(())
                } else {
                    Self::send_auth_reply(stream, AuthStatus::Failure).await?;
                    Err(SocksError::AuthFailed("invalid credentials".into()))
                }
            }

            _ => Err(SocksError::AuthFailed("no acceptable method".into())),
        }
    }
}
