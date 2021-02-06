//! # hyper-alpn
//!
//! An Alpn connector to be used with [hyper](https://hyper.rs).
//!
//! ## Example
//!
//! ```no_run
//! use futures::{future, Future};
//! use hyper_alpn::AlpnConnector;
//! use hyper::Client;
//!
//! fn main() {
//!     let mut builder = Client::builder();
//!     builder.http2_only(true);
//!
//!     let client: Client<AlpnConnector> = builder.build(AlpnConnector::new());
//! }
//! ```

#[macro_use]
extern crate log;

use hyper::client::connect::{Connected, Connection};
use hyper::{service::Service, Uri};
use rustls::internal::pemfile;
use std::{
    fmt,
    future::Future,
    io,
    net::{self, ToSocketAddrs},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, TlsConnector};
use webpki::{DNSName, DNSNameRef};

/// Connector for Application-Layer Protocol Negotiation to form a TLS
/// connection for Hyper.
#[derive(Clone)]
pub struct AlpnConnector {
    config: Arc<ClientConfig>,
}

#[derive(Debug)]
pub struct AlpnStream(TlsStream<TcpStream>);

impl AsyncRead for AlpnStream {
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut Pin::get_mut(self).0).poll_read(cx, buf)
    }
}

impl AsyncWrite for AlpnStream {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut Pin::get_mut(self).0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut Pin::get_mut(self).0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut Pin::get_mut(self).0).poll_shutdown(cx)
    }
}

impl Connection for AlpnStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AlpnConnector {
    /// Construct a new `AlpnConnector`.
    pub fn new() -> Self {
        Self::with_client_config(ClientConfig::new())
    }

    /// Construct a new `AlpnConnector` with a custom certificate and private
    /// key, which should be in PEM format.
    ///
    /// ```no_run
    /// extern crate openssl;
    /// extern crate hyper;
    /// extern crate hyper_alpn;
    /// extern crate futures;
    /// extern crate tokio;
    ///
    /// use futures::{future, Future};
    /// use hyper_alpn::AlpnConnector;
    /// use hyper::Client;
    /// use openssl::pkcs12::Pkcs12;
    /// use std::{fs::File, io::Read};
    ///
    /// fn main() {
    ///     let mut certificate = File::open("path/to/cert.p12").unwrap();
    ///     let mut der: Vec<u8> = Vec::new();
    ///     certificate.read_to_end(&mut der).unwrap();
    ///
    ///     let pkcs = Pkcs12::from_der(&der)
    ///         .unwrap()
    ///         .parse("my_p12_password")
    ///         .unwrap();
    ///
    ///     let connector = AlpnConnector::with_client_cert(
    ///         &pkcs.cert.to_pem().unwrap(),
    ///         &pkcs.pkey.private_key_to_pem_pkcs8().unwrap(),
    ///     ).unwrap();
    ///
    ///     let mut builder = Client::builder();
    ///     builder.http2_only(true);
    ///
    ///     let client: Client<AlpnConnector> = builder.build(connector);
    /// }
    /// ```
    pub fn with_client_cert(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, io::Error> {
        let parsed_keys = pemfile::pkcs8_private_keys(&mut io::BufReader::new(key_pem)).or({
            trace!("AlpnConnector::with_client_cert error reading private key");
            Err(io::Error::new(io::ErrorKind::InvalidData, "private key"))
        })?;

        if let Some(key) = parsed_keys.first() {
            let mut config = ClientConfig::new();

            let parsed_cert = pemfile::certs(&mut io::BufReader::new(cert_pem)).or({
                trace!("AlpnConnector::with_client_cert error reading certificate");
                Err(io::Error::new(io::ErrorKind::InvalidData, "certificate"))
            })?;

            config.set_single_client_cert(parsed_cert, key.clone()).or_else(|e| {
                trace!("AlpnConnector::with_client_cert error reading certificate");
                Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))
            })?;

            Ok(Self::with_client_config(config))
        } else {
            trace!("AlpnConnector::with_client_cert no private keys found from the given PEM");
            Err(io::Error::new(io::ErrorKind::InvalidData, "private key"))
        }
    }

    fn with_client_config(mut config: ClientConfig) -> Self {
        config.alpn_protocols.push("h2".as_bytes().to_vec());
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        AlpnConnector {
            config: Arc::new(config),
        }
    }

    async fn resolve(dst: Uri) -> std::io::Result<net::SocketAddr> {
        let port = dst.port_u16().unwrap_or(443);
        let host = dst.host().unwrap_or("localhost").to_string();

        let mut addrs = tokio::task::spawn_blocking(move || (host.as_str(), port).to_socket_addrs())
            .await
            .unwrap()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Couldn't resolve host: {:?}", e)))?;

        addrs.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Could not resolve host: no address(es) returned".to_string(),
            )
        })
    }
}

impl fmt::Debug for AlpnConnector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AlpnConnector").finish()
    }
}

impl Service<Uri> for AlpnConnector {
    type Response = AlpnStream;
    type Error = io::Error;
    type Future = AlpnConnecting;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        trace!("AlpnConnector::call ({:?})", dst);

        let host = dst.host().unwrap_or("localhost");
        let host: DNSName = match DNSNameRef::try_from_ascii_str(host) {
            Ok(host) => host.into(),
            Err(err) => {
                let err = io::Error::new(io::ErrorKind::InvalidInput, format!("invalid url: {:?}", err));

                return AlpnConnecting(Box::pin(async { Err(err) }));
            }
        };

        let config = self.config.clone();

        let fut = async move {
            let socket = Self::resolve(dst).await?;
            let tcp = TcpStream::connect(&socket).await?;

            trace!("AlpnConnector::call got TCP, trying TLS");

            let connector = TlsConnector::from(config);

            match connector.connect(host.as_ref(), tcp).await {
                Ok(tls) => Ok(AlpnStream(tls)),
                Err(e) => {
                    trace!("AlpnConnector::call got error forming a TLS connection.");
                    Err(io::Error::new(io::ErrorKind::Other, e))
                }
            }
        };

        AlpnConnecting(Box::pin(fut))
    }
}

type BoxedFut = Pin<Box<dyn Future<Output = io::Result<AlpnStream>> + Send>>;

pub struct AlpnConnecting(BoxedFut);

impl Future for AlpnConnecting {
    type Output = Result<AlpnStream, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl fmt::Debug for AlpnConnecting {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("AlpnConnecting")
    }
}

#[cfg(test)]
mod tests {
    use super::AlpnConnector;
    use hyper::Uri;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_resolving() {
        let dst: Uri = "http://theinstituteforendoticresearch.org:80".parse().unwrap();
        let expected: SocketAddr = "162.213.255.73:80".parse().unwrap();

        assert_eq!(expected, AlpnConnector::resolve(dst).await.unwrap(),)
    }
}
