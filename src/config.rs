use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use anyhow::Result;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub https_bind: SocketAddr,
    pub rtsp_bind: SocketAddr,
    pub onvif_bind: SocketAddr,
    pub http_bind: SocketAddr,
    pub onvif2_bind: SocketAddr,
    pub onvif_event_bind: SocketAddr,
    pub upstream_https_host: String,
    pub upstream_https_port: u16,
    pub upstream_rtsp_host: String,
    pub upstream_rtsp_port: u16,
    pub upstream_onvif_host: String,
    pub upstream_onvif_port: u16,
    pub upstream_http_host: String,
    pub upstream_http_port: u16,
    pub upstream_onvif2_host: String,
    pub upstream_onvif2_port: u16,
    pub upstream_onvif_event_host: String,
    pub upstream_onvif_event_port: u16,
    pub public_host: String,
    pub public_https_port: u16,
    pub public_http_port: u16,
    pub public_rtsp_port: u16,
    pub public_onvif_port: u16,
    pub public_onvif2_port: u16,
    pub public_onvif_event_port: u16,
    pub rtsp_force_tcp: bool,
    pub debug: bool,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
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

        let rtsp_force_tcp = env::var("RTSP_FORCE_TCP")
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
            rtsp_force_tcp,
            debug,
        })
    }
}
