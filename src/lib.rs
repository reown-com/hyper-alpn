//! # hyper-alpn
//!
//! An Alpn connector to be used with [hyper](https://hyper.rs).
//!
//! ## Example
//!
//! ```no_run
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

#![allow(clippy::needless_doctest_main)]

#[macro_use]
extern crate log;

use hyper::client::connect::{Connected, Connection};
use hyper::{service::Service, Uri};
use rustls::client::WantsTransparencyPolicyOrClientCert;
use rustls::{self, ConfigBuilder, OwnedTrustAnchor, ServerName, WantsCipherSuites};
use std::convert::TryFrom;
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

/// Connector for Application-Layer Protocol Negotiation to form a TLS
/// connection for Hyper.
#[derive(Clone)]
pub struct AlpnConnector {
    config: Option<Arc<ClientConfig>>,
    config_builder: ConfigBuilder<ClientConfig, WantsTransparencyPolicyOrClientCert>,
}

impl AlpnConnector {
    /// Builds the `config_builder` and places it in `config` provided that `config` is `None`.
    fn build_config(&mut self) {
        if self.config.is_some() {
            return;
        }

        let mut config = self.config_builder.clone().with_no_client_auth();
        config.alpn_protocols.push("h2".as_bytes().to_vec());
        self.config = Some(Arc::new(config));
    }

    /// Builds the `config_builder` with a certificate and places it in `config` provided that `config` is `None`.
    fn build_config_with_certificate(
        &mut self,
        cert_chain: Vec<rustls::Certificate>,
        key_der: Vec<u8>,
    ) -> Result<(), rustls::Error> {
        if self.config.is_some() {
            return Ok(());
        }

        let config = self
            .config_builder
            .clone()
            .with_client_auth_cert(cert_chain, rustls::PrivateKey(key_der));
        match config {
            Ok(mut c) => {
                c.alpn_protocols.push("h2".as_bytes().to_vec());
                self.config = Some(Arc::new(c));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl Default for AlpnConnector {
    fn default() -> Self {
        Self::new()
    }
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
        Self::with_client_config(ClientConfig::builder())
    }

    /// Construct a new `AlpnConnector` with a custom certificate and private
    /// key, which should be in PEM format.
    ///
    /// ```no_run
    /// extern crate openssl;
    /// extern crate hyper;
    /// extern crate hyper_alpn;
    /// extern crate tokio;
    ///
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
        let parsed_keys = rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(key_pem)).or({
            trace!("AlpnConnector::with_client_cert error reading private key");
            Err(io::Error::new(io::ErrorKind::InvalidData, "private key"))
        })?;

        if let Some(key) = parsed_keys.first() {
            let parsed_cert = rustls_pemfile::certs(&mut io::BufReader::new(cert_pem))
                .or({
                    trace!("AlpnConnector::with_client_cert error reading private key");
                    Err(io::Error::new(io::ErrorKind::InvalidData, "private key"))
                })?
                .into_iter()
                .map(rustls::Certificate)
                .collect::<Vec<rustls::Certificate>>();

            let mut c = Self::with_client_config(ClientConfig::builder());
            c.build_config_with_certificate(parsed_cert, key.clone()).or({
                trace!("AlpnConnector::build_config_with_certificate invalid key");
                Err(io::Error::new(io::ErrorKind::InvalidData, "key"))
            })?;

            Ok(c)
        } else {
            trace!("AlpnConnector::with_client_cert no private keys found from the given PEM");
            Err(io::Error::new(io::ErrorKind::InvalidData, "private key"))
        }
    }

    fn with_client_config(config: ConfigBuilder<ClientConfig, WantsCipherSuites>) -> Self {
        let mut root_cert_store = rustls::RootCertStore::empty();

        root_cert_store.add_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
            }),
        );

        let config = config.with_safe_defaults().with_root_certificates(root_cert_store);

        AlpnConnector {
            config: None,
            config_builder: config,
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
        let host = match ServerName::try_from(host) {
            Ok(host) => host,
            Err(err) => {
                let err = io::Error::new(io::ErrorKind::InvalidInput, format!("invalid url: {:?}", err));

                return AlpnConnecting(Box::pin(async { Err(err) }));
            }
        };

        // TODO: Revisit this, hotfix for now
        if self.config.is_none() {
            self.build_config()
        }

        let config = self.config.clone().unwrap();

        let fut = async move {
            let socket = Self::resolve(dst).await?;
            let tcp = TcpStream::connect(&socket).await?;

            trace!("AlpnConnector::call got TCP, trying TLS");

            let connector = TlsConnector::from(config);

            match connector.connect(host, tcp).await {
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
