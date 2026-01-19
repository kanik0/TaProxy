use anyhow::{Context, Result};
use native_tls::TlsConnector as NativeTlsBuilder;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::TlsConnector as NativeTlsConnector;
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

use crate::{config::AppConfig, logging::log_debug};

pub fn build_native_tls_connector() -> Result<NativeTlsConnector> {
    let mut builder = NativeTlsBuilder::builder();
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
    Ok(NativeTlsConnector::from(builder.build()?))
}

pub fn generate_tls_server_config() -> Result<ServerConfig> {
    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

    let cert = rcgen::Certificate::from_params(params)?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(server_config)
}

pub async fn run_https_proxy(
    acceptor: TlsAcceptor,
    connector: NativeTlsConnector,
    cfg: AppConfig,
) -> Result<()> {
    let listener = TcpListener::bind(cfg.https_bind)
        .await
        .with_context(|| format!("binding HTTPS listener on {}", cfg.https_bind))?;
    println!("HTTPS proxy listening on {}", cfg.https_bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let cfg_clone = cfg.clone();
        let acceptor = acceptor.clone();
        let connector = connector.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_https_client(acceptor, connector, cfg_clone, socket).await {
                eprintln!("[HTTPS] client {peer}: {err:?}");
            }
        });
    }
}

async fn handle_https_client(
    acceptor: TlsAcceptor,
    connector: NativeTlsConnector,
    cfg: AppConfig,
    socket: TcpStream,
) -> Result<()> {
    log_debug(&cfg, "HTTPS: inbound TLS handshake start");
    let mut inbound_tls = acceptor
        .accept(socket)
        .await
        .context("TLS handshake with client")?;

    let upstream_host = cfg.upstream_https_host.clone();
    let upstream_port = cfg.upstream_https_port;

    log_debug(
        &cfg,
        format!("HTTPS: connecting upstream {upstream_host}:{upstream_port}"),
    );
    let upstream_stream = TcpStream::connect((upstream_host.as_str(), upstream_port))
        .await
        .with_context(|| {
            format!(
                "connecting to upstream HTTPS {}:{}",
                upstream_host, upstream_port
            )
        })?;

    let mut outbound_tls = connector
        .connect(upstream_host.as_str(), upstream_stream)
        .await
        .context("TLS handshake with upstream")?;

    log_debug(&cfg, "HTTPS: piping traffic");
    let _ = copy_bidirectional(&mut inbound_tls, &mut outbound_tls).await?;
    Ok(())
}
