use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
}

impl Socks5 {
    pub async fn new(addr: &str) -> Result<Socks5, SocksError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Socks5 { listener })
    }

    pub async fn run(&mut self) -> Result<(), SocksError> {
        println!("SOCKS5 server running on {:?}", self.listener.local_addr()?);
        loop {
            let (mut stream, addr) = self.listener.accept().await?;
            println!("Accepted connection from {:?}", addr);
            tokio::spawn(async move {
                if let Err(e) = handle_client(&mut stream).await {
                    eprintln!("Error handling client {}: {:?}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(stream: &mut TcpStream) -> Result<(), SocksError> {
    let mut buf = [0u8; 512];

    // --- SOCKS5 handshake ---
    let n = stream.read(&mut buf).await?;
    let version_msg = VersionMessage::try_from(&buf[..n])?;
    println!("Client methods: {:?}", version_msg.methods);

    let selected_method = version_msg
        .methods
        .iter()
        .find_map(|m| match m {
            Method::Fixed(FixedMethod::UsePass) => Some(Method::Fixed(FixedMethod::UsePass)),
            Method::Fixed(FixedMethod::NoAuth) => Some(Method::Fixed(FixedMethod::NoAuth)),
            _ => None,
        })
        .unwrap_or(Method::Fixed(FixedMethod::NoAcceptable));

    let method_sel = msg::message::MethodSelection::new(selected_method);
    stream.write_all(&method_sel.to_bytes()).await?;
    if selected_method == Method::Fixed(FixedMethod::NoAcceptable) {
        println!("No acceptable authentication methods.");
        stream.shutdown().await?;
        return Ok(());
    }

    // --- Username/Password authentication (RFC 1929) ---
    if selected_method == Method::Fixed(FixedMethod::UsePass) {
        let n = stream.read(&mut buf).await?;
        let auth_req = AuthRequest::try_from(&buf[..n])?;
        println!(
            "Auth request received: username={}, password={}",
            auth_req.uname, auth_req.passwd
        );

        let expected_user =
            env::var("PROXY_USER").map_err(|e| SocksError::AuthFailed(e.to_string()))?;
        let expected_pass =
            env::var("PROXY_PASS").map_err(|e| SocksError::AuthFailed(e.to_string()))?;

        let auth_status = if auth_req.uname == expected_user && auth_req.passwd == expected_pass {
            AuthStatus::Success
        } else {
            AuthStatus::Failure
        };

        let auth_reply = AuthReply::new(auth_status);
        stream.write_all(&auth_reply.to_bytes()).await?;

        if auth_status == AuthStatus::Failure {
            println!("Authentication failed for user '{}'", auth_req.uname);
            stream.shutdown().await?;
            return Ok(());
        }

        println!("Authentication successful for user '{}'", auth_req.uname);
    }

    // --- SOCKS5 request ---
    let n = stream.read(&mut buf).await?;
    let request = ConnRequest::try_from(&buf[..n])?;

    println!("Received SOCKS5 request:");
    println!("  Version: {}", request.ver);
    println!("  Command: {:?}", request.cmd);
    println!("  Reserved: {}", request.rsv);
    println!("  Address type: {:?}", request.atyp);

    match &request.dst {
        AddrPort::V4(ip, port) => println!("  AddrPort: IPv4 {}:{}", ip, port),
        AddrPort::V6(ip, port) => println!("  AddrPort: IPv6 [{}]:{}", ip, port),
        AddrPort::Domain(name, port) => println!("  AddrPort: Domain {}:{}", name, port),
    }

    let target_result = match &request.dst {
        AddrPort::V4(ip, port) => TcpStream::connect((*ip, *port)).await,
        AddrPort::V6(ip, port) => TcpStream::connect((*ip, *port)).await,
        AddrPort::Domain(name, port) => TcpStream::connect((name.as_str(), *port)).await,
    };

    let mut target_stream = match target_result {
        Ok(s) => s,
        Err(_) => {
            println!("Failed to connect to target");
            let reply = ConnReply::new(
                VER5,
                Rep::HostUnreachable,
                RSV,
                ATYP::V4,
                AddrPort::V4(Ipv4Addr::UNSPECIFIED, 0),
            );
            stream.write_all(&reply.to_bytes()).await?;
            stream.shutdown().await?;
            return Ok(());
        }
    };

    let local_addr = target_stream.local_addr()?;
    let bnd = match local_addr.ip() {
        IpAddr::V4(ip) => AddrPort::V4(ip, local_addr.port()),
        IpAddr::V6(ip) => AddrPort::V6(ip, local_addr.port()),
    };

    let reply = ConnReply::new(
        VER5,
        Rep::Succeeded,
        RSV,
        match bnd {
            AddrPort::V4(_, _) => ATYP::V4,
            AddrPort::V6(_, _) => ATYP::V6,
            _ => ATYP::DomainName,
        },
        bnd,
    );

    stream.write_all(&reply.to_bytes()).await?;

    if tokio::io::copy_bidirectional(stream, &mut target_stream)
        .await
        .is_err()
    {
        println!("TCP connection closed");
    }

    Ok(())
}

