use crate::config::AppConfig;

pub fn rewrite_onvif_body(body: &str, cfg: &AppConfig) -> String {
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

    out = out.replace(&cfg.upstream_http_host, &cfg.public_host);
    out
}
