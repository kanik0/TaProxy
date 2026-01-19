use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    config::AppConfig,
    logging::{
        log_body_snippet, log_body_url, log_body_urls, log_debug, log_http_summary,
        log_onvif_request_actions, log_onvif_tag_values, log_rewrite_check,
    },
    onvif_rewrite::rewrite_onvif_body,
};

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

pub async fn handle_http_like(
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
        if rewrite {
            let body_text = String::from_utf8_lossy(&request.body);
            log_onvif_request_actions(&cfg, kind, &body_text);
        }
        let request_bytes = assemble_http_message(
            &request.start_line,
            &request.header_lines,
            &request.body,
            request.chunked,
        );
        out_w.write_all(&request_bytes).await?;

        let Some(response) = out_reader.read_http_message().await? else {
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
            log_body_urls(&cfg, kind, &body_text);
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

pub async fn run_http_proxy(cfg: AppConfig) -> Result<()> {
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
