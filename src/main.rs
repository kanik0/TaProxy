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
    onvif_event_bind: SocketAddr,
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
    upstream_onvif_event_host: String,
    upstream_onvif_event_port: u16,
    public_host: String,
    public_https_port: u16,
    public_http_port: u16,
    public_rtsp_port: u16,
    public_onvif_port: u16,
    public_onvif2_port: u16,
    public_onvif_event_port: u16,
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
        let onvif_event_bind_port = env::var("ONVIF_EVENT_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1025);

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
        let upstream_onvif_event_port = env::var("UPSTREAM_ONVIF_EVENT_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1025);

        let public_host = env::var("PUBLIC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let public_https_port = env::var("PUBLIC_HTTPS_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(https_bind_port);
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
        let public_onvif_event_port = env::var("PUBLIC_ONVIF_EVENT_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(onvif_event_bind_port);

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
            onvif_event_bind: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                onvif_event_bind_port,
            ),
            upstream_https_host: upstream_host.clone(),
            upstream_https_port,
            upstream_rtsp_host: upstream_host.clone(),
            upstream_rtsp_port,
            upstream_onvif_host: upstream_host.clone(),
            upstream_onvif_port,
            upstream_http_host: upstream_host.clone(),
            upstream_http_port,
            upstream_onvif2_host: upstream_host.clone(),
            upstream_onvif2_port,
            upstream_onvif_event_host: upstream_host,
            upstream_onvif_event_port,
            public_host,
            public_https_port,
            public_http_port,
            public_rtsp_port,
            public_onvif_port,
            public_onvif2_port,
            public_onvif_event_port,
            debug,
        })
    }
}

fn log_debug(cfg: &AppConfig, msg: impl AsRef<str>) {
    if cfg.debug {
        println!("[DEBUG] {}", msg.as_ref());
    }
}

fn log_http_summary(
    cfg: &AppConfig,
    kind: &str,
    direction: &str,
    start: &str,
    headers: &[String],
    body_len: usize,
) {
    if !cfg.debug {
        return;
    }
    let mut host = None;
    let mut soap_action = None;
    let mut content_length = None;
    for line in headers {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            host = Some(line.clone());
        } else if lower.starts_with("soapaction:") {
            soap_action = Some(line.clone());
        } else if lower.starts_with("content-length:") {
            content_length = Some(line.clone());
        }
    }
    let host_line = host.unwrap_or_else(|| "Host: (none)".to_string());
    let soap_line = soap_action.unwrap_or_else(|| "SOAPAction: (none)".to_string());
    let len_line = content_length.unwrap_or_else(|| "Content-Length: (none)".to_string());
    println!(
        "[DEBUG] {kind}: {direction} {start} | {host_line} | {len_line} | {soap_line} | body={body_len}"
    );
}

fn log_body_snippet(cfg: &AppConfig, kind: &str, body: &[u8]) {
    if !cfg.debug {
        return;
    }
    let text = String::from_utf8_lossy(body);
    let snippet: String = text.chars().take(600).collect();
    let sanitized = snippet.replace('\r', "\\r").replace('\n', "\\n");
    println!("[DEBUG] {kind}: body snippet: {sanitized}");
}

fn log_body_url(cfg: &AppConfig, kind: &str, body: &[u8]) {
    if !cfg.debug {
        return;
    }
    let text = String::from_utf8_lossy(body);
    let host_needles = [
        cfg.upstream_https_host.as_str(),
        cfg.upstream_http_host.as_str(),
        cfg.upstream_rtsp_host.as_str(),
    ];
    if let Some((idx, needle)) = host_needles
        .iter()
        .filter_map(|n| text.find(n).map(|idx| (idx, *n)))
        .min_by_key(|(idx, _)| *idx)
    {
        let start = idx.saturating_sub(40);
        let end = (idx + needle.len() + 200).min(text.len());
        let snippet = &text[start..end];
        let sanitized = snippet.replace('\r', "\\r").replace('\n', "\\n");
        println!("[DEBUG] {kind}: host snippet: {sanitized}");
        return;
    }

    let scheme_needles = ["http://", "https://", "rtsp://"];
    if let Some((idx, needle)) = scheme_needles
        .iter()
        .filter_map(|n| text.find(n).map(|idx| (idx, *n)))
        .min_by_key(|(idx, _)| *idx)
    {
        let start = idx.saturating_sub(40);
        let end = (idx + needle.len() + 200).min(text.len());
        let snippet = &text[start..end];
        let sanitized = snippet.replace('\r', "\\r").replace('\n', "\\n");
        println!("[DEBUG] {kind}: url snippet: {sanitized}");
    }
}

fn log_rewrite_check(cfg: &AppConfig, kind: &str, original: &str, rewritten: &str, upstream: &str) {
    if !cfg.debug {
        return;
    }
    if original == rewritten {
        if let Some(idx) = original.find(upstream) {
            let start = idx.saturating_sub(40);
            let end = (idx + upstream.len() + 120).min(original.len());
            let snippet = &original[start..end];
            let sanitized = snippet.replace('\r', "\\r").replace('\n', "\\n");
            println!("[DEBUG] {kind}: rewrite unchanged, upstream still present: {sanitized}");
        }
    } else {
        if let Some(idx) = rewritten.find(upstream) {
            let start = idx.saturating_sub(40);
            let end = (idx + upstream.len() + 120).min(rewritten.len());
            let snippet = &rewritten[start..end];
            let sanitized = snippet.replace('\r', "\\r").replace('\n', "\\n");
            println!("[DEBUG] {kind}: rewrite still contains upstream: {sanitized}");
        } else {
            println!("[DEBUG] {kind}: rewrite removed upstream host references");
        }
    }
}

fn log_onvif_tag_values(cfg: &AppConfig, kind: &str, body: &str) {
    if !cfg.debug {
        return;
    }
    let tags = [
        "XAddr",
        "Address",
        "SnapshotUri",
        "Uri",
        "StreamUri",
        "MetadataStreamUri",
        "Rtsp",
    ];
    for tag in tags {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        if let (Some(start), Some(end)) = (body.find(&open), body.find(&close)) {
            if end > start + open.len() {
                let value = &body[start + open.len()..end];
                let sanitized = value.replace('\r', "\\r").replace('\n', "\\n");
                println!("[DEBUG] {kind}: tag {tag} = {sanitized}");
            }
        }
    }
}

#[derive(Debug)]
struct HttpMessage {
    start_line: String,
    header_lines: Vec<String>,
    body: Vec<u8>,
    chunked: bool,
}

struct HttpReader<R> {
    reader: R,
    buf: Vec<u8>,
}

impl<R: AsyncReadExt + Unpin> HttpReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
        }
    }

    async fn read_line(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let mut line = self.buf.drain(..=pos).collect::<Vec<u8>>();
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }

            let mut tmp = [0u8; 1024];
            let n = self.reader.read(&mut tmp).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let remaining = self.buf.split_off(0);
                return Ok(Some(remaining));
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn read_exact_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        while self.buf.len() < len {
            let mut tmp = [0u8; 4096];
            let n = self.reader.read(&mut tmp).await?;
            if n == 0 {
                return Err(anyhow::anyhow!("unexpected EOF while reading body"));
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
        let out = self.buf.drain(..len).collect::<Vec<u8>>();
        Ok(out)
    }

    async fn read_http_message(&mut self) -> Result<Option<HttpMessage>> {
        let start_line_bytes = match self.read_line().await? {
            Some(line) => line,
            None => return Ok(None),
        };
        if start_line_bytes.is_empty() {
            return Ok(None);
        }

        let start_line = String::from_utf8_lossy(&start_line_bytes).to_string();
        let mut header_lines = Vec::new();
        let mut content_length = None;
        let mut chunked = false;

        loop {
            let line = self.read_line().await?;
            let Some(line_bytes) = line else {
                break;
            };
            if line_bytes.is_empty() {
                break;
            }
            let line_str = String::from_utf8_lossy(&line_bytes).to_string();
            let lower = line_str.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-length:") {
                content_length = rest.trim().parse::<usize>().ok();
            }
            if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
            header_lines.push(line_str);
        }

        let body = if chunked {
            let mut out = Vec::new();
            loop {
                let size_line_bytes = self
                    .read_line()
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("unexpected EOF while reading chunk size"))?;
                let size_line = String::from_utf8_lossy(&size_line_bytes);
                let size_hex = size_line.trim();
                let size = usize::from_str_radix(size_hex, 16)
                    .map_err(|_| anyhow::anyhow!("invalid chunk size: {size_hex}"))?;
                if size == 0 {
                    // Trailers, if any, end with an empty line.
                    loop {
                        let trailer_line = self
                            .read_line()
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("unexpected EOF in trailers"))?;
                        if trailer_line.is_empty() {
                            break;
                        }
                    }
                    break;
                }
                let chunk = self.read_exact_bytes(size).await?;
                out.extend_from_slice(&chunk);
                let _ = self.read_exact_bytes(2).await?;
            }
            out
        } else if let Some(len) = content_length {
            if len == 0 {
                Vec::new()
            } else {
                self.read_exact_bytes(len).await?
            }
        } else {
            Vec::new()
        };

        Ok(Some(HttpMessage {
            start_line,
            header_lines,
            body,
            chunked,
        }))
    }
}

fn assemble_http_message(
    start_line: &str,
    header_lines: &[String],
    body: &[u8],
    remove_chunked: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(start_line.as_bytes());
    out.extend_from_slice(b"\r\n");

    let mut wrote_length = false;
    for line in header_lines {
        let lower = line.to_ascii_lowercase();
        if remove_chunked && lower.starts_with("transfer-encoding:") {
            continue;
        }
        if lower.starts_with("content-length:") {
            out.extend_from_slice(format!("Content-Length: {}", body.len()).as_bytes());
            out.extend_from_slice(b"\r\n");
            wrote_length = true;
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    if !wrote_length {
        out.extend_from_slice(format!("Content-Length: {}", body.len()).as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

async fn handle_http_like(
    cfg: AppConfig,
    mut inbound: TcpStream,
    upstream_host: String,
    upstream_port: u16,
    kind: &str,
    rewrite: bool,
) -> Result<()> {
    log_debug(
        &cfg,
        format!("{kind}: connecting upstream {upstream_host}:{upstream_port}"),
    );
    let mut outbound = TcpStream::connect((upstream_host.as_str(), upstream_port))
        .await
        .with_context(|| {
            format!("connecting to upstream {kind} {upstream_host}:{upstream_port}")
        })?;

    let (in_r, mut in_w) = inbound.split();
    let (out_r, mut out_w) = outbound.split();
    let mut in_reader = HttpReader::new(in_r);
    let mut out_reader = HttpReader::new(out_r);

    loop {
        let Some(request) = in_reader.read_http_message().await? else {
            break;
        };
        log_http_summary(
            &cfg,
            kind,
            "request",
            &request.start_line,
            &request.header_lines,
            request.body.len(),
        );
        let request_bytes = assemble_http_message(
            &request.start_line,
            &request.header_lines,
            &request.body,
            request.chunked,
        );
        out_w.write_all(&request_bytes).await?;

        let Some(mut response) = out_reader.read_http_message().await? else {
            break;
        };
        log_http_summary(
            &cfg,
            kind,
            "response",
            &response.start_line,
            &response.header_lines,
            response.body.len(),
        );
        log_body_snippet(&cfg, kind, &response.body);
        log_body_url(&cfg, kind, &response.body);
        let mut body = response.body;
        if rewrite {
            let body_text = String::from_utf8_lossy(&body);
            log_onvif_tag_values(&cfg, kind, &body_text);
            let rewritten = rewrite_onvif_body(&body_text, &cfg);
            log_rewrite_check(
                &cfg,
                kind,
                &body_text,
                &rewritten,
                cfg.upstream_http_host.as_str(),
            );
            if rewritten.as_bytes() != body.as_slice() {
                log_debug(&cfg, format!("{kind}: response body rewritten"));
            }
            body = rewritten.into_bytes();
        }

        let response_bytes = assemble_http_message(
            &response.start_line,
            &response.header_lines,
            &body,
            response.chunked,
        );
        in_w.write_all(&response_bytes).await?;
    }

    Ok(())
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
        "Starting proxy: HTTPS {} -> {}:{} | RTSP {} -> {}:{} | ONVIF {} -> {}:{} | HTTP {} -> {}:{} | ONVIF2 {} -> {}:{} | ONVIF-EVENT {} -> {}:{}",
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
        config.upstream_onvif2_port,
        config.onvif_event_bind,
        config.upstream_onvif_event_host,
        config.upstream_onvif_event_port
    );
    println!(
        "Public endpoints: host={} https={} http={} rtsp={} onvif={} onvif2={} onvif-event={}",
        config.public_host,
        config.public_https_port,
        config.public_http_port,
        config.public_rtsp_port,
        config.public_onvif_port,
        config.public_onvif2_port,
        config.public_onvif_event_port
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
    let onvif_event_task = tokio::spawn(run_onvif_event_proxy(config.clone()));

    let (https_res, rtsp_res, onvif_res, http_res, onvif2_res, onvif_event_res) = tokio::try_join!(
        https_task,
        rtsp_task,
        onvif_task,
        http_task,
        onvif2_task,
        onvif_event_task
    )
    .map_err(|join_err| anyhow::anyhow!("Task join error: {join_err}"))?;

    https_res?;
    rtsp_res?;
    onvif_res?;
    http_res?;
    onvif2_res?;
    onvif_event_res?;
    Ok(())
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

async fn handle_http_client(cfg: AppConfig, inbound: TcpStream) -> Result<()> {
    let upstream_host = cfg.upstream_http_host.clone();
    let upstream_port = cfg.upstream_http_port;
    handle_http_like(cfg, inbound, upstream_host, upstream_port, "HTTP", true).await
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

async fn handle_onvif_client(cfg: AppConfig, inbound: TcpStream) -> Result<()> {
    let upstream_host = cfg.upstream_onvif_host.clone();
    let upstream_port = cfg.upstream_onvif_port;
    handle_http_like(cfg, inbound, upstream_host, upstream_port, "ONVIF", true).await
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

async fn handle_onvif2_client(cfg: AppConfig, inbound: TcpStream) -> Result<()> {
    let upstream_host = cfg.upstream_onvif2_host.clone();
    let upstream_port = cfg.upstream_onvif2_port;
    handle_http_like(cfg, inbound, upstream_host, upstream_port, "ONVIF2", true).await
}

async fn run_onvif_event_proxy(cfg: AppConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.onvif_event_bind)
        .await
        .with_context(|| format!("binding ONVIF-EVENT listener on {}", cfg.onvif_event_bind))?;
    println!("ONVIF-EVENT proxy listening on {}", cfg.onvif_event_bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_onvif_event_client(cfg_clone, socket).await {
                eprintln!("[ONVIF-EVENT] client {peer}: {err:?}");
            }
        });
    }
}

async fn handle_onvif_event_client(cfg: AppConfig, inbound: TcpStream) -> Result<()> {
    let upstream_host = cfg.upstream_onvif_event_host.clone();
    let upstream_port = cfg.upstream_onvif_event_port;
    handle_http_like(
        cfg,
        inbound,
        upstream_host,
        upstream_port,
        "ONVIF-EVENT",
        true,
    )
    .await
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

    let upstream_http_no_port = format!("http://{}", cfg.upstream_http_host);
    let public_http_no_port = format!("http://{}", cfg.public_host);
    out = out.replace(&upstream_http_no_port, &public_http_no_port);

    let upstream_http_any_port = format!("http://{}:", cfg.upstream_http_host);
    let public_http_any_port = format!("http://{}:", cfg.public_host);
    out = out.replace(&upstream_http_any_port, &public_http_any_port);

    let upstream_https = format!(
        "https://{}:{}",
        cfg.upstream_https_host, cfg.upstream_https_port
    );
    let public_https = format!("https://{}:{}", cfg.public_host, cfg.public_https_port);
    out = out.replace(&upstream_https, &public_https);

    let upstream_https_no_port = format!("https://{}", cfg.upstream_https_host);
    let public_https_no_port = format!("https://{}", cfg.public_host);
    out = out.replace(&upstream_https_no_port, &public_https_no_port);

    let upstream_https_any_port = format!("https://{}:", cfg.upstream_https_host);
    let public_https_any_port = format!("https://{}:", cfg.public_host);
    out = out.replace(&upstream_https_any_port, &public_https_any_port);

    let upstream_rtsp = format!(
        "rtsp://{}:{}",
        cfg.upstream_rtsp_host, cfg.upstream_rtsp_port
    );
    let public_rtsp = format!("rtsp://{}:{}", cfg.public_host, cfg.public_rtsp_port);
    out = out.replace(&upstream_rtsp, &public_rtsp);

    let upstream_rtsp_no_port = format!("rtsp://{}", cfg.upstream_rtsp_host);
    let public_rtsp_no_port = format!("rtsp://{}", cfg.public_host);
    out = out.replace(&upstream_rtsp_no_port, &public_rtsp_no_port);

    let upstream_rtsp_any_port = format!("rtsp://{}:", cfg.upstream_rtsp_host);
    let public_rtsp_any_port = format!("rtsp://{}:", cfg.public_host);
    out = out.replace(&upstream_rtsp_any_port, &public_rtsp_any_port);

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

    let upstream_onvif_event = format!(
        "http://{}:{}",
        cfg.upstream_onvif_event_host, cfg.upstream_onvif_event_port
    );
    let public_onvif_event = format!("http://{}:{}", cfg.public_host, cfg.public_onvif_event_port);
    out = out.replace(&upstream_onvif_event, &public_onvif_event);

    // Also replace bare hosts if present without ports
    out = out.replace(&cfg.upstream_http_host, &cfg.public_host);
    out
}
