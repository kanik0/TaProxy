use crate::config::AppConfig;

pub fn log_debug(cfg: &AppConfig, msg: impl AsRef<str>) {
    if cfg.debug {
        println!("[DEBUG] {}", msg.as_ref());
    }
}

pub fn log_http_summary(
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

pub fn log_body_snippet(cfg: &AppConfig, kind: &str, body: &[u8]) {
    if !cfg.debug {
        return;
    }
    let text = String::from_utf8_lossy(body);
    let snippet: String = text.chars().take(600).collect();
    let sanitized = snippet.replace('\r', "\\r").replace('\n', "\\n");
    println!("[DEBUG] {kind}: body snippet: {sanitized}");
}

pub fn log_body_url(cfg: &AppConfig, kind: &str, body: &[u8]) {
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

pub fn log_rewrite_check(cfg: &AppConfig, kind: &str, original: &str, rewritten: &str, upstream: &str) {
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
    } else if let Some(idx) = rewritten.find(upstream) {
        let start = idx.saturating_sub(40);
        let end = (idx + upstream.len() + 120).min(rewritten.len());
        let snippet = &rewritten[start..end];
        let sanitized = snippet.replace('\r', "\\r").replace('\n', "\\n");
        println!("[DEBUG] {kind}: rewrite still contains upstream: {sanitized}");
    } else {
        println!("[DEBUG] {kind}: rewrite removed upstream host references");
    }
}

pub fn log_onvif_tag_values(cfg: &AppConfig, kind: &str, body: &str) {
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

pub fn log_onvif_request_actions(cfg: &AppConfig, kind: &str, body: &str) {
    if !cfg.debug {
        return;
    }
    let actions = [
        "GetStreamUri",
        "GetSnapshotUri",
        "GetProfiles",
        "GetCapabilities",
        "GetServices",
        "CreatePullPointSubscription",
        "PullMessages",
        "GetEventProperties",
    ];
    let mut found = Vec::new();
    for action in actions {
        if body.contains(action) {
            found.push(action);
        }
    }
    if !found.is_empty() {
        let joined = found.join(", ");
        println!("[DEBUG] {kind}: request actions = {joined}");
    }
}

pub fn log_body_urls(cfg: &AppConfig, kind: &str, body: &str) {
    if !cfg.debug {
        return;
    }
    let mut urls = Vec::new();
    let bytes = body.as_bytes();
    let schemes: [&[u8]; 3] = [b"http://", b"https://", b"rtsp://"];
    let mut i = 0;
    while i < bytes.len() {
        let mut matched = None;
        for scheme in schemes {
            if bytes[i..].starts_with(scheme) {
                matched = Some(scheme);
                break;
            }
        }
        if let Some(scheme) = matched {
            let start = i;
            let mut end = i + scheme.len();
            while end < bytes.len() {
                let b = bytes[end];
                if b == b'<' || b == b'"' || b == b'\'' || b == b' ' || b == b'\r' || b == b'\n' {
                    break;
                }
                end += 1;
            }
            if end > start {
                if let Ok(url) = std::str::from_utf8(&bytes[start..end]) {
                    if !urls.contains(&url.to_string()) {
                        urls.push(url.to_string());
                    }
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }

    if !urls.is_empty() {
        let host_urls = urls
            .iter()
            .filter(|u| u.contains(&cfg.upstream_http_host) || u.contains(&cfg.public_host))
            .cloned()
            .collect::<Vec<_>>();
        let list = if !host_urls.is_empty() {
            host_urls
        } else {
            urls.into_iter().take(10).collect()
        };
        let joined = list.join(" | ");
        println!("[DEBUG] {kind}: urls = {joined}");
    }
}

pub fn log_rtsp_rewrite(cfg: &AppConfig, head: &[u8], body: &[u8]) {
    if !cfg.debug {
        return;
    }
    let head_text = String::from_utf8_lossy(head);
    for line in head_text.split("\r\n") {
        if line.to_ascii_lowercase().starts_with("content-base:") {
            log_debug(cfg, format!("RTSP: rewritten Content-Base: {line}"));
        }
    }
    if !body.is_empty() {
        let body_text = String::from_utf8_lossy(body);
        for line in body_text.lines() {
            if line.starts_with("a=control:") {
                log_debug(cfg, format!("RTSP: SDP control: {line}"));
            }
        }
    }
}

pub fn log_rtsp_sdp(cfg: &AppConfig, body: &[u8]) {
    if !cfg.debug {
        return;
    }
    if body.is_empty() {
        return;
    }
    let body_text = String::from_utf8_lossy(body);
    for line in body_text.lines() {
        if line.starts_with("m=") || line.starts_with("a=") || line.starts_with("c=") {
            log_debug(cfg, format!("RTSP: SDP line: {line}"));
        }
    }
}

pub fn log_rtsp_headers(cfg: &AppConfig, kind: &str, lines: &[String]) {
    if !cfg.debug {
        return;
    }
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization:") || lower.starts_with("proxy-authorization:") {
            log_debug(
                cfg,
                format!(
                    "RTSP: {kind} header: {}: <redacted>",
                    line.split(':').next().unwrap_or("authorization")
                ),
            );
            continue;
        }
        if lower.starts_with("cseq:")
            || lower.starts_with("session:")
            || lower.starts_with("transport:")
            || lower.starts_with("public:")
            || lower.starts_with("content-base:")
            || lower.starts_with("content-length:")
        {
            log_debug(cfg, format!("RTSP: {kind} header: {line}"));
        }
    }
}

pub fn log_rtsp_transport_line(cfg: &AppConfig, kind: &str, lines: &[String]) {
    if !cfg.debug {
        return;
    }
    for line in lines {
        if line.to_ascii_lowercase().starts_with("transport:") {
            log_debug(cfg, format!("RTSP: {kind} transport: {line}"));
        }
    }
}
