use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time::{self, Duration},
};

use crate::{
    config::AppConfig,
    logging::{
        log_debug, log_rtsp_headers, log_rtsp_rewrite, log_rtsp_sdp, log_rtsp_transport_line,
    },
};

pub async fn run_rtsp_proxy(cfg: AppConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.rtsp_bind)
        .await
        .with_context(|| format!("binding RTSP listener on {}", cfg.rtsp_bind))?;
    println!("RTSP proxy listening on {}", cfg.rtsp_bind);

    loop {
        let (socket, peer) = listener.accept().await?;
        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_rtsp_client(cfg_clone, socket, peer).await {
                eprintln!("[RTSP] client {peer}: {err:?}");
            }
        });
    }
}

async fn handle_rtsp_client(cfg: AppConfig, mut inbound: TcpStream, peer: std::net::SocketAddr) -> Result<()> {
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

    let mut handshake_count = 0usize;
    loop {
        handshake_count += 1;
        log_debug(&cfg, "RTSP: reading request headers");
        let mut first_byte = [0u8; 1];
        let n = inbound.read(&mut first_byte).await?;
        if n == 0 {
            break;
        }
        if first_byte[0] == b'$' {
            log_debug(&cfg, "RTSP: interleaved frame from client");
            forward_interleaved_frame(&mut inbound, &mut outbound, &first_byte).await?;
            continue;
        }

        let request_buf = read_rtsp_headers_with_prefix(&mut inbound, 16384, &first_byte).await?;
        let Some(request_buf) = request_buf else {
            break;
        };

        let mut request_lines = split_rtsp_lines(&request_buf);
        if let Some(line) = request_lines.first() {
            log_debug(&cfg, format!("RTSP: request line: {line}"));
        }
        let method = request_lines
            .first()
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_default()
            .to_string();

        let mut pending_udp: Option<UdpSetup> = None;
        if method.eq_ignore_ascii_case("SETUP") {
            if cfg.rtsp_force_tcp {
                rewrite_rtsp_transport_to_tcp(&mut request_lines);
            } else if let Some((client_rtp, client_rtcp)) = extract_client_ports(&request_lines) {
                let udp_pair = bind_udp_pair().await?;
                let proxy_rtp = udp_pair.0.local_addr()?.port();
                let proxy_rtcp = udp_pair.1.local_addr()?.port();
                log_debug(
                    &cfg,
                    format!(
                        "RTSP: UDP setup client ports {client_rtp}-{client_rtcp}, proxy ports {proxy_rtp}-{proxy_rtcp}"
                    ),
                );
                rewrite_rtsp_client_ports(&mut request_lines, proxy_rtp, proxy_rtcp);
                log_rtsp_transport_line(&cfg, "request rewritten", &request_lines);
                pending_udp = Some(UdpSetup {
                    client_addr: std::net::SocketAddr::new(peer.ip(), client_rtp),
                    client_rtcp,
                    proxy_rtp,
                    proxy_rtcp,
                    udp_rtp: udp_pair.0,
                    udp_rtcp: udp_pair.1,
                });
            } else {
                log_debug(&cfg, "RTSP: UDP setup missing client_port in request");
            }
        }

        log_rtsp_headers(&cfg, "request", &request_lines);
        let rebuilt_request = join_rtsp_lines(&request_lines);
        outbound.write_all(&rebuilt_request).await?;

        log_debug(&cfg, "RTSP: reading response headers");
        let response_buf = read_rtsp_headers(&mut outbound, 16384).await?;
        let Some(response_buf) = response_buf else {
            break;
        };
        let mut response_lines = split_rtsp_lines(&response_buf);
        if let Some(line) = response_lines.first() {
            log_debug(&cfg, format!("RTSP: response line: {line}"));
        }
        log_rtsp_headers(&cfg, "response", &response_lines);

        let (content_length, has_content_base) = extract_rtsp_response_info(&response_lines);
        if let Some(udp_setup) = pending_udp.take() {
            if let Some((server_rtp, server_rtcp)) = extract_server_ports(&response_lines) {
                rewrite_rtsp_server_ports(
                    &mut response_lines,
                    udp_setup.proxy_rtp,
                    udp_setup.proxy_rtcp,
                );
                log_rtsp_transport_line(&cfg, "response rewritten", &response_lines);
                let cam_addr = std::net::SocketAddr::new(
                    cfg.upstream_rtsp_host.parse().unwrap_or_else(|_| peer.ip()),
                    server_rtp,
                );
                spawn_udp_proxy(
                    udp_setup.udp_rtp,
                    udp_setup.udp_rtcp,
                    udp_setup.client_addr,
                    std::net::SocketAddr::new(peer.ip(), udp_setup.client_rtcp),
                    cam_addr,
                    std::net::SocketAddr::new(cam_addr.ip(), server_rtcp),
                );
                log_debug(
                    &cfg,
                    format!(
                        "RTSP: UDP proxy client {}:{} / {}:{} <-> camera {}:{} / {}:{}",
                        udp_setup.client_addr.ip(),
                        udp_setup.client_addr.port(),
                        peer.ip(),
                        udp_setup.client_rtcp,
                        cam_addr.ip(),
                        server_rtp,
                        cam_addr.ip(),
                        server_rtcp
                    ),
                );
            } else {
                log_debug(&cfg, "RTSP: UDP setup missing server_port in response");
            }
        }
        if let Some(len) = content_length {
            let body = read_exact_from_stream(&mut outbound, len).await?;
            let response_buf = join_rtsp_lines(&response_lines);
            let (rewritten_head, rewritten_body) = if method.eq_ignore_ascii_case("DESCRIBE") {
                rewrite_rtsp_describe_response(&response_buf, &body, &cfg)?
            } else if has_content_base {
                rewrite_rtsp_headers_only(&response_buf, &cfg)?
            } else {
                (response_buf.clone(), body)
            };
            if method.eq_ignore_ascii_case("DESCRIBE") {
                log_rtsp_rewrite(&cfg, &rewritten_head, &rewritten_body);
                log_rtsp_sdp(&cfg, &rewritten_body);
            }
            inbound.write_all(&rewritten_head).await?;
            inbound.write_all(&rewritten_body).await?;
        } else {
            let response_buf = join_rtsp_lines(&response_lines);
            let rewritten_head = if method.eq_ignore_ascii_case("DESCRIBE") || has_content_base {
                rewrite_rtsp_headers_only(&response_buf, &cfg)?.0
            } else {
                response_buf
            };
            if method.eq_ignore_ascii_case("DESCRIBE") {
                log_rtsp_rewrite(&cfg, &rewritten_head, &[]);
            }
            inbound.write_all(&rewritten_head).await?;
        }

        if method.eq_ignore_ascii_case("PLAY") || handshake_count >= 20 {
            break;
        }
    }

    log_debug(&cfg, "RTSP: piping traffic");
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

fn rewrite_rtsp_transport_to_tcp(lines: &mut [String]) {
    let mut next_interleaved = 0;
    for line in lines.iter_mut() {
        if line.to_ascii_lowercase().starts_with("transport:") {
            let mut new_line = String::from("Transport: RTP/AVP/TCP;unicast;interleaved=");
            new_line.push_str(&format!("{}-{}", next_interleaved, next_interleaved + 1));
            *line = new_line;
            next_interleaved += 2;
        }
    }
}

fn join_rtsp_lines(lines: &[String]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(&lines.join("\r\n"));
    out.push_str("\r\n\r\n");
    out.into_bytes()
}

struct UdpSetup {
    client_addr: std::net::SocketAddr,
    client_rtcp: u16,
    proxy_rtp: u16,
    proxy_rtcp: u16,
    udp_rtp: UdpSocket,
    udp_rtcp: UdpSocket,
}

async fn bind_udp_pair() -> Result<(UdpSocket, UdpSocket)> {
    for _ in 0..50 {
        let rtp = UdpSocket::bind("0.0.0.0:0").await?;
        let port = rtp.local_addr()?.port();
        if port % 2 != 0 {
            continue;
        }
        let rtcp_addr = format!("0.0.0.0:{}", port + 1);
        if let Ok(rtcp) = UdpSocket::bind(rtcp_addr).await {
            return Ok((rtp, rtcp));
        }
    }
    let rtp = UdpSocket::bind("0.0.0.0:0").await?;
    let rtcp = UdpSocket::bind("0.0.0.0:0").await?;
    Ok((rtp, rtcp))
}

fn extract_client_ports(lines: &[String]) -> Option<(u16, u16)> {
    for line in lines {
        if !line.to_ascii_lowercase().starts_with("transport:") {
            continue;
        }
        if let Some((rtp, rtcp)) = parse_port_pair(line, "client_port") {
            return Some((rtp, rtcp));
        }
    }
    None
}

fn extract_server_ports(lines: &[String]) -> Option<(u16, u16)> {
    for line in lines {
        if !line.to_ascii_lowercase().starts_with("transport:") {
            continue;
        }
        if let Some((rtp, rtcp)) = parse_port_pair(line, "server_port") {
            return Some((rtp, rtcp));
        }
    }
    None
}

fn parse_port_pair(line: &str, key: &str) -> Option<(u16, u16)> {
    let lower = line.to_ascii_lowercase();
    for part in lower.split(';') {
        let part = part.trim();
        let Some(rest) = part.strip_prefix(&format!("{key}=")) else {
            continue;
        };
        let mut iter = rest.split('-');
        let rtp = iter.next()?.parse().ok()?;
        let rtcp = iter.next()?.parse().ok()?;
        return Some((rtp, rtcp));
    }
    None
}

fn rewrite_rtsp_client_ports(lines: &mut [String], rtp: u16, rtcp: u16) {
    for line in lines.iter_mut() {
        if !line.to_ascii_lowercase().starts_with("transport:") {
            continue;
        }
        *line = replace_port_pair(line, "client_port", rtp, rtcp);
    }
}

fn rewrite_rtsp_server_ports(lines: &mut [String], rtp: u16, rtcp: u16) {
    for line in lines.iter_mut() {
        if !line.to_ascii_lowercase().starts_with("transport:") {
            continue;
        }
        *line = replace_port_pair(line, "server_port", rtp, rtcp);
    }
}

fn replace_port_pair(line: &str, key: &str, rtp: u16, rtcp: u16) -> String {
    let mut parts: Vec<String> = line.split(';').map(|s| s.trim().to_string()).collect();
    let mut replaced = false;
    for part in parts.iter_mut() {
        if part.to_ascii_lowercase().starts_with(&format!("{key}=")) {
            *part = format!("{key}={rtp}-{rtcp}");
            replaced = true;
        }
    }
    if !replaced {
        parts.push(format!("{key}={rtp}-{rtcp}"));
    }
    parts.join(";")
}

fn spawn_udp_proxy(
    rtp: UdpSocket,
    rtcp: UdpSocket,
    client_rtp: std::net::SocketAddr,
    client_rtcp: std::net::SocketAddr,
    cam_rtp: std::net::SocketAddr,
    cam_rtcp: std::net::SocketAddr,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<(String, usize)>();
    let stats_task = tokio::spawn(async move {
        let mut rtp_in = 0usize;
        let mut rtp_out = 0usize;
        let mut rtcp_in = 0usize;
        let mut rtcp_out = 0usize;
        let mut ticker = time::interval(Duration::from_secs(2));
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if rtp_in > 0 || rtp_out > 0 || rtcp_in > 0 || rtcp_out > 0 {
                        println!(
                            "[DEBUG] RTSP: UDP stats rtp_in={} rtp_out={} rtcp_in={} rtcp_out={}",
                            rtp_in, rtp_out, rtcp_in, rtcp_out
                        );
                        rtp_in = 0;
                        rtp_out = 0;
                        rtcp_in = 0;
                        rtcp_out = 0;
                    }
                }
                msg = rx.recv() => {
                    let Some((kind, bytes)) = msg else {
                        break;
                    };
                    match kind.as_str() {
                        "rtp_in" => rtp_in += bytes,
                        "rtp_out" => rtp_out += bytes,
                        "rtcp_in" => rtcp_in += bytes,
                        "rtcp_out" => rtcp_out += bytes,
                        _ => {}
                    }
                }
            }
        }
    });

    let tx_rtp = tx.clone();
    let tx_rtcp = tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, src) = match rtp.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let _ = tx_rtp.send(("rtp_in".to_string(), n));
            let dst = if src.ip() == cam_rtp.ip() {
                client_rtp
            } else {
                cam_rtp
            };
            if rtp.send_to(&buf[..n], dst).await.is_ok() {
                let _ = tx_rtp.send(("rtp_out".to_string(), n));
            }
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, src) = match rtcp.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let _ = tx_rtcp.send(("rtcp_in".to_string(), n));
            let dst = if src.ip() == cam_rtcp.ip() {
                client_rtcp
            } else {
                cam_rtcp
            };
            if rtcp.send_to(&buf[..n], dst).await.is_ok() {
                let _ = tx_rtcp.send(("rtcp_out".to_string(), n));
            }
        }
    });

    tokio::spawn(async move {
        let _ = stats_task.await;
    });
}

fn extract_rtsp_response_info(lines: &[String]) -> (Option<usize>, bool) {
    let mut content_length = None;
    let mut has_content_base = false;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse::<usize>().ok();
        }
        if lower.starts_with("content-base:") {
            has_content_base = true;
        }
    }
    (content_length, has_content_base)
}

fn rewrite_rtsp_headers_only(response_buf: &[u8], cfg: &AppConfig) -> Result<(Vec<u8>, Vec<u8>)> {
    let text = String::from_utf8_lossy(response_buf);
    let (head, _) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid RTSP headers"))?;
    let mut lines = Vec::new();
    for line in head.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("content-base:") {
            let rewritten = rewrite_rtsp_url(line, cfg);
            lines.push(rewritten);
        } else {
            lines.push(line.to_string());
        }
    }
    let mut out = String::new();
    out.push_str(&lines.join("\r\n"));
    out.push_str("\r\n\r\n");
    Ok((out.into_bytes(), Vec::new()))
}

fn rewrite_rtsp_describe_response(
    response_buf: &[u8],
    body: &[u8],
    cfg: &AppConfig,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let text = String::from_utf8_lossy(response_buf);
    let (head, _) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid RTSP headers"))?;
    let mut lines = Vec::new();
    for line in head.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-base:") {
            lines.push(rewrite_rtsp_url(line, cfg));
        } else if lower.starts_with("content-length:") {
            let rewritten_body = rewrite_rtsp_body(body, cfg);
            lines.push(format!("Content-Length: {}", rewritten_body.len()));
            let mut out = String::new();
            out.push_str(&lines.join("\r\n"));
            out.push_str("\r\n\r\n");
            return Ok((out.into_bytes(), rewritten_body));
        } else {
            lines.push(line.to_string());
        }
    }

    let rewritten_body = rewrite_rtsp_body(body, cfg);
    lines.push(format!("Content-Length: {}", rewritten_body.len()));
    let mut out = String::new();
    out.push_str(&lines.join("\r\n"));
    out.push_str("\r\n\r\n");
    Ok((out.into_bytes(), rewritten_body))
}

fn rewrite_rtsp_url(line: &str, cfg: &AppConfig) -> String {
    let upstream = format!(
        "rtsp://{}:{}",
        cfg.upstream_rtsp_host, cfg.upstream_rtsp_port
    );
    let public = format!("rtsp://{}:{}", cfg.public_host, cfg.public_rtsp_port);
    let upstream_any_port = format!("rtsp://{}:", cfg.upstream_rtsp_host);
    let public_any_port = format!("rtsp://{}:", cfg.public_host);
    line.replace(&upstream, &public)
        .replace(&upstream_any_port, &public_any_port)
}

fn rewrite_rtsp_body(body: &[u8], cfg: &AppConfig) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let upstream = format!(
        "rtsp://{}:{}",
        cfg.upstream_rtsp_host, cfg.upstream_rtsp_port
    );
    let public = format!("rtsp://{}:{}", cfg.public_host, cfg.public_rtsp_port);
    let upstream_any_port = format!("rtsp://{}:", cfg.upstream_rtsp_host);
    let public_any_port = format!("rtsp://{}:", cfg.public_host);
    let rewritten = text
        .replace(&upstream, &public)
        .replace(&upstream_any_port, &public_any_port);
    rewritten.into_bytes()
}

async fn read_exact_from_stream(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn read_rtsp_headers_with_prefix(
    stream: &mut TcpStream,
    max_len: usize,
    prefix: &[u8],
) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(prefix);
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(buf));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(Some(buf));
        }
        if buf.len() >= max_len {
            return Ok(Some(buf));
        }
    }
}

async fn read_rtsp_headers(stream: &mut TcpStream, max_len: usize) -> Result<Option<Vec<u8>>> {
    read_rtsp_headers_with_prefix(stream, max_len, &[]).await
}

async fn forward_interleaved_frame(
    inbound: &mut TcpStream,
    outbound: &mut TcpStream,
    first: &[u8; 1],
) -> Result<()> {
    let mut header = [0u8; 3];
    inbound.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    let mut payload = vec![0u8; len];
    inbound.read_exact(&mut payload).await?;

    outbound.write_all(first).await?;
    outbound.write_all(&header).await?;
    outbound.write_all(&payload).await?;
    Ok(())
}

fn split_rtsp_lines(buf: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(buf);
    text.split("\r\n")
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect()
}
