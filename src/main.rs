use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use native_tls::TlsConnector as NativeTlsBuilder;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::TlsConnector as NativeTlsConnector;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

#[derive(Clone, Debug)]
struct AppConfig {
    https_bind: SocketAddr,
    rtsp_bind: SocketAddr,
    onvif_bind: SocketAddr,
    http_bind: SocketAddr,
    onvif2_bind: SocketAddr,
    upstream_https_host: String,
    upstream_https_port: u16,
    upstream_rtsp_host: String,
    upstream_rtsp_port: u16,
    upstream_onvif_host: String,
    upstream_onvif_port: u16,
    upstream_http_host: String,
    upstream_http_port: u16,
    upstream_onvif2_host: String,
    upstream_onvif2_port: u16,
    public_host: String,
    public_http_port: u16,
    public_rtsp_port: u16,
    public_onvif_port: u16,
    public_onvif2_port: u16,
    debug: bool,
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        let https_bind_port = env::var("HTTPS_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(443);
        let rtsp_bind_port = env::var("RTSP_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(554);
        let onvif_bind_port = env::var("ONVIF_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2020);
        let http_bind_port = env::var("HTTP_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8800);
        let onvif2_bind_port = env::var("ONVIF2_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);

        let upstream_host = env::var("UPSTREAM_HOST").unwrap_or_else(|_| "10.66.0.201".to_string());
        let upstream_https_port = env::var("UPSTREAM_HTTPS_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(443);
        let upstream_rtsp_port = env::var("UPSTREAM_RTSP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(554);
        let upstream_onvif_port = env::var("UPSTREAM_ONVIF_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2020);
        let upstream_http_port = env::var("UPSTREAM_HTTP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8800);
        let upstream_onvif2_port = env::var("UPSTREAM_ONVIF2_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);

        let public_host = env::var("PUBLIC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let public_http_port = env::var("PUBLIC_HTTP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(http_bind_port);
        let public_rtsp_port = env::var("PUBLIC_RTSP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(rtsp_bind_port);
        let public_onvif_port = env::var("PUBLIC_ONVIF_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(onvif_bind_port);
        let public_onvif2_port = env::var("PUBLIC_ONVIF2_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(onvif2_bind_port);

        let debug = env::var("PROXY_DEBUG")
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        Ok(Self {
            https_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), https_bind_port),
            rtsp_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), rtsp_bind_port),
            onvif_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), onvif_bind_port),
            http_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), http_bind_port),
            onvif2_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), onvif2_bind_port),
            upstream_https_host: upstream_host.clone(),
            upstream_https_port,
            upstream_rtsp_host: upstream_host.clone(),
            upstream_rtsp_port,
            upstream_onvif_host: upstream_host.clone(),
            upstream_onvif_port,
            upstream_http_host: upstream_host.clone(),
            upstream_http_port,
            upstream_onvif2_host: upstream_host,
            upstream_onvif2_port,
            public_host,
            public_http_port,
            public_rtsp_port,
            public_onvif_port,
            public_onvif2_port,
            debug,
        })
    }
}

fn log_debug(cfg: &AppConfig, msg: impl AsRef<str>) {
    if cfg.debug {
        println!("[DEBUG] {}", msg.as_ref());
    }
}

fn build_native_tls_connector() -> Result<NativeTlsConnector> {
    let mut builder = NativeTlsBuilder::builder();
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
    Ok(NativeTlsConnector::from(builder.build()?))
}

fn generate_tls_server_config() -> Result<ServerConfig> {
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

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::from_env()?;
    println!(
        "Starting proxy: HTTPS {} -> {}:{} | RTSP {} -> {}:{} | ONVIF {} -> {}:{} | HTTP {} -> {}:{} | ONVIF2 {} -> {}:{}",
        config.https_bind,
        config.upstream_https_host,
        config.upstream_https_port,
        config.rtsp_bind,
        config.upstream_rtsp_host,
        config.upstream_rtsp_port,
        config.onvif_bind,
        config.upstream_onvif_host,
        config.upstream_onvif_port,
        config.http_bind,
        config.upstream_http_host,
        config.upstream_http_port,
        config.onvif2_bind,
        config.upstream_onvif2_host,
        config.upstream_onvif2_port
    );

    let tls_acceptor = TlsAcceptor::from(Arc::new(generate_tls_server_config()?));
    let native_tls_connector = build_native_tls_connector()?;

    let https_task = tokio::spawn(run_https_proxy(
        tls_acceptor,
        native_tls_connector.clone(),
        config.clone(),
    ));
    let rtsp_task = tokio::spawn(run_rtsp_proxy(config.clone()));
    let onvif_task = tokio::spawn(run_onvif_proxy(config.clone()));
    let http_task = tokio::spawn(run_http_proxy(config.clone()));
    let onvif2_task = tokio::spawn(run_onvif2_proxy(config.clone()));

    match tokio::try_join!(https_task, rtsp_task, onvif_task, http_task, onvif2_task) {
        Ok((Ok(_), Ok(_), Ok(_), Ok(_), Ok(_))) => Ok(()),
        Ok((Err(e), _, _, _, _))
        | Ok((_, Err(e), _, _, _))
        | Ok((_, _, Err(e), _, _))
        | Ok((_, _, _, Err(e), _))
        | Ok((_, _, _, _, Err(e))) => Err(e),
        Err(join_err) => Err(anyhow::anyhow!("Task join error: {join_err}")),
    }
}

async fn run_https_proxy(
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

async fn run_rtsp_proxy(cfg: AppConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.rtsp_bind)
        .await
        .with_context(|| format!("binding RTSP listener on {}", cfg.rtsp_bind))?;
    println!("RTSP proxy listening on {}", cfg.rtsp_bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_rtsp_client(cfg_clone, socket).await {
                eprintln!("[RTSP] client {peer}: {err:?}");
            }
        });
    }
}

async fn handle_rtsp_client(cfg: AppConfig, mut inbound: TcpStream) -> Result<()> {
    log_debug(
        &cfg,
        format!(
            "RTSP: connecting upstream {}:{}",
            cfg.upstream_rtsp_host, cfg.upstream_rtsp_port
        ),
    );
    let mut outbound =
        TcpStream::connect((cfg.upstream_rtsp_host.as_str(), cfg.upstream_rtsp_port))
            .await
            .with_context(|| {
                format!(
                    "connecting to upstream RTSP {}:{}",
                    cfg.upstream_rtsp_host, cfg.upstream_rtsp_port
                )
            })?;

    log_debug(&cfg, "RTSP: piping traffic");
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

async fn run_http_proxy(cfg: AppConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.http_bind)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.http_bind))?;
    println!("HTTP proxy listening on {}", cfg.http_bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_http_client(cfg_clone, socket).await {
                eprintln!("[HTTP] client {peer}: {err:?}");
            }
        });
    }
}

async fn handle_http_client(cfg: AppConfig, mut inbound: TcpStream) -> Result<()> {
    log_debug(
        &cfg,
        format!(
            "HTTP: connecting upstream {}:{}",
            cfg.upstream_http_host, cfg.upstream_http_port
        ),
    );
    let mut outbound =
        TcpStream::connect((cfg.upstream_http_host.as_str(), cfg.upstream_http_port))
            .await
            .with_context(|| {
                format!(
                    "connecting to upstream HTTP {}:{}",
                    cfg.upstream_http_host, cfg.upstream_http_port
                )
            })?;

    log_debug(&cfg, "HTTP: reading request");
    let mut request = Vec::new();
    inbound.read_to_end(&mut request).await?;
    outbound.write_all(&request).await?;

    let mut response = Vec::new();
    outbound.read_to_end(&mut response).await?;

    if let Some(rewritten) = rewrite_http_response(&response, &cfg) {
        log_debug(&cfg, "HTTP: response rewritten");
        inbound.write_all(&rewritten).await?;
    } else {
        inbound.write_all(&response).await?;
    }

    Ok(())
}

async fn run_onvif_proxy(cfg: AppConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.onvif_bind)
        .await
        .with_context(|| format!("binding ONVIF listener on {}", cfg.onvif_bind))?;
    println!("ONVIF proxy listening on {}", cfg.onvif_bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_onvif_client(cfg_clone, socket).await {
                eprintln!("[ONVIF] client {peer}: {err:?}");
            }
        });
    }
}

async fn handle_onvif_client(cfg: AppConfig, mut inbound: TcpStream) -> Result<()> {
    log_debug(
        &cfg,
        format!(
            "ONVIF: connecting upstream {}:{}",
            cfg.upstream_onvif_host, cfg.upstream_onvif_port
        ),
    );
    let mut outbound =
        TcpStream::connect((cfg.upstream_onvif_host.as_str(), cfg.upstream_onvif_port))
            .await
            .with_context(|| {
                format!(
                    "connecting to upstream ONVIF {}:{}",
                    cfg.upstream_onvif_host, cfg.upstream_onvif_port
                )
            })?;

    log_debug(&cfg, "ONVIF: piping traffic");
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

async fn run_onvif2_proxy(cfg: AppConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.onvif2_bind)
        .await
        .with_context(|| format!("binding ONVIF2 listener on {}", cfg.onvif2_bind))?;
    println!("ONVIF2 proxy listening on {}", cfg.onvif2_bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_onvif2_client(cfg_clone, socket).await {
                eprintln!("[ONVIF2] client {peer}: {err:?}");
            }
        });
    }
}

async fn handle_onvif2_client(cfg: AppConfig, mut inbound: TcpStream) -> Result<()> {
    log_debug(
        &cfg,
        format!(
            "ONVIF2: connecting upstream {}:{}",
            cfg.upstream_onvif2_host, cfg.upstream_onvif2_port
        ),
    );
    let mut outbound =
        TcpStream::connect((cfg.upstream_onvif2_host.as_str(), cfg.upstream_onvif2_port))
            .await
            .with_context(|| {
                format!(
                    "connecting to upstream ONVIF2 {}:{}",
                    cfg.upstream_onvif2_host, cfg.upstream_onvif2_port
                )
            })?;

    log_debug(&cfg, "ONVIF2: piping traffic");
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

fn rewrite_http_response(buf: &[u8], cfg: &AppConfig) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(buf);
    let split = text.split_once("\r\n\r\n")?;
    let (head, body) = split;
    let mut content_length: Option<usize> = None;
    let mut headers = Vec::new();

    for line in head.lines() {
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            content_length = rest.trim().parse::<usize>().ok();
        }
        headers.push(line);
    }

    let new_body = rewrite_onvif_body(body, cfg);
    if let Some(len) = content_length {
        if len != body.len() {
            // Only rewrite when lengths match expected body; otherwise, fallback
            if len != body.as_bytes().len() {
                return None;
            }
        }
    }

    let mut new_headers = Vec::new();
    for line in headers {
        if line.starts_with("Content-Length:") {
            new_headers.push(format!("Content-Length: {}", new_body.len()));
        } else {
            new_headers.push(line.to_string());
        }
    }

    let mut out = String::new();
    out.push_str(&new_headers.join("\r\n"));
    out.push_str("\r\n\r\n");
    out.push_str(&new_body);
    Some(out.into_bytes())
}

fn rewrite_onvif_body(body: &str, cfg: &AppConfig) -> String {
    let mut out = body.to_string();

    let upstream_http = format!(
        "http://{}:{}",
        cfg.upstream_http_host, cfg.upstream_http_port
    );
    let public_http = format!("http://{}:{}", cfg.public_host, cfg.public_http_port);
    out = out.replace(&upstream_http, &public_http);

    let upstream_rtsp = format!(
        "rtsp://{}:{}",
        cfg.upstream_rtsp_host, cfg.upstream_rtsp_port
    );
    let public_rtsp = format!("rtsp://{}:{}", cfg.public_host, cfg.public_rtsp_port);
    out = out.replace(&upstream_rtsp, &public_rtsp);

    let upstream_onvif = format!(
        "http://{}:{}",
        cfg.upstream_onvif_host, cfg.upstream_onvif_port
    );
    let public_onvif = format!("http://{}:{}", cfg.public_host, cfg.public_onvif_port);
    out = out.replace(&upstream_onvif, &public_onvif);

    let upstream_onvif2 = format!(
        "http://{}:{}",
        cfg.upstream_onvif2_host, cfg.upstream_onvif2_port
    );
    let public_onvif2 = format!("http://{}:{}", cfg.public_host, cfg.public_onvif2_port);
    out = out.replace(&upstream_onvif2, &public_onvif2);

    // Also replace bare hosts if present without ports
    out = out.replace(&cfg.upstream_http_host, &cfg.public_host);
    out
}
