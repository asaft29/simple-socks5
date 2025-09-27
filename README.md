# simple-socks5

`simple-socks5` is a lightweight, asynchronous Rust library that makes it easy to run a SOCKS5 proxy server, following [RFC 1928](https://tools.ietf.org/html/rfc1928). 

It’s designed to be used **with web browsers as clients**, and has been tested with Firefox and Chromium using both "No Authentication" and "Username/Password" authentication ([RFC 1929](https://tools.ietf.org/html/rfc1929)).

> **Disclaimer:** UDP is not yet fully supported. It will be added in the future, so do **not use UDP** for now—stick to TCP (`CONNECT`/`BIND`).

## Example

A rather basic SOCKS5 proxy server is included in the repository:

```bash
cargo run --example simple_server --release
```

## How to use

Add this to your `Cargo.toml`:

```toml
[dependencies]
simple-socks5 = "0.1.0"

