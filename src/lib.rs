//! A minimal asynchronous SOCKS5 proxy implementation using Tokio.
//!
//! This crate provides structures and helpers for handling the SOCKS5 protocol
//! (RFC 1928) and optional username/password authentication (RFC 1929).
//! It supports TCP `CONNECT`, `BIND`, and `UDP ASSOCIATE` commands, with
//! configurable authentication methods.
//!
//! **UDP functionality is not yet fully implemented.**
//! The server can bind a UDP socket and send a `UDP ASSOCIATE` reply, but
//! actual UDP packet forwarding and relay logic is not handled yet.
//! Users should not rely on UDP support for production usage.

use std::fmt;
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

type UserPassValidator = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Represents the address type in SOCKS5 messages.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ATYP {
    /// IPv4 address
    V4 = 0x01,
    /// Domain name
    DomainName = 0x03,
    /// IPv6 address
    V6 = 0x04,
}

impl fmt::Display for ATYP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ATYP::V4 => write!(f, "IPv4"),
            ATYP::V6 => write!(f, "IPv6"),
            ATYP::DomainName => write!(f, "Domain"),
        }
    }
}

/// The main SOCKS5 server struct.
///
/// Handles incoming TCP connections, negotiates authentication, and manages
/// SOCKS5 commands (`CONNECT`, `BIND`, `UDP ASSOCIATE`).
///
/// **⚠️ UDP ASSOCIATE is partially implemented.**
/// The server currently only supports binding a UDP socket and sending the
/// reply to the client. Actual UDP packet forwarding is **not implemented** yet.
pub struct Socks5 {
    listener: TcpListener,
    allow_no_auth: bool,
    userpass_validator: Option<UserPassValidator>,
}

impl Socks5 {
    /// Bind a new SOCKS5 server to an address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to bind to, e.g., `"127.0.0.1:1080"`.
    ///
    /// # Errors
    ///
    /// Returns a `SocksError::Io` if binding fails.
    pub async fn bind(addr: &str) -> Result<Self, SocksError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            allow_no_auth: false,
            userpass_validator: None,
        })
    }

    /// Enable the `NO AUTH` authentication method.
    pub fn allow_no_auth(&mut self) {
        self.allow_no_auth = true;
    }

    /// Enable username/password authentication with a custom validator closure.
    ///
    /// # Arguments
    ///
    /// * `validator` - A closure that receives username and password and returns `true` if valid.
    pub fn allow_userpass<F>(&mut self, validator: F)
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.userpass_validator = Some(Box::new(validator));
    }

    /// Accept a client TCP connection.
    ///
    /// # Returns
    ///
    /// A tuple of `(TcpStream, SocketAddr)` representing the connected client.
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), SocksError> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((stream, addr))
    }

    /// Returns the local address of the server.
    pub fn local_addr(&self) -> Result<SocketAddr, SocksError> {
        Ok(self.listener.local_addr()?)
    }

    // --- Protocol helpers ---

    /// Read a SOCKS5 version/method message from the client.
    pub async fn read_version_message(
        stream: &mut TcpStream,
    ) -> Result<VersionMessage, SocksError> {
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        VersionMessage::try_from(&buf[..n])
    }

    /// Send the server's method selection message.
    pub async fn send_method_selection(
        stream: &mut TcpStream,
        method: Method,
    ) -> Result<(), SocksError> {
        let sel = MethodSelection::new(method);
        stream.write_all(&sel.to_bytes()).await?;
        Ok(())
    }

    /// Read a username/password authentication request from the client.
    pub async fn read_auth_request(stream: &mut TcpStream) -> Result<AuthRequest, SocksError> {
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        AuthRequest::try_from(&buf[..n])
    }

    /// Send an authentication reply to the client.
    pub async fn send_auth_reply(
        stream: &mut TcpStream,
        status: AuthStatus,
    ) -> Result<(), SocksError> {
        let reply = AuthReply::new(status);
        stream.write_all(&reply.to_bytes()).await?;
        Ok(())
    }

    /// Read a SOCKS5 connection request from the client.
    pub async fn read_conn_request(stream: &mut TcpStream) -> Result<ConnRequest, SocksError> {
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await?;
        ConnRequest::try_from(&buf[..n])
    }

    /// Send a connection reply to the client.
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

    /// Bind a UDP socket for `UDP ASSOCIATE`.
    ///
    /// **Actual UDP relay is not implemented yet.**
    pub async fn bind_udp(addr: &str) -> Result<UdpSocket, SocksError> {
        let sock = UdpSocket::bind(addr).await?;
        Ok(sock)
    }

    /// Perform authentication according to the configured methods.
    ///
    /// Negotiates between `NO AUTH` and `USERNAME/PASSWORD` methods if enabled.
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
