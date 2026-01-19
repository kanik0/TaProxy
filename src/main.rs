mod config;
mod http_proxy;
mod logging;
mod onvif_proxy;
mod onvif_rewrite;
mod rtsp_proxy;
mod tls_proxy;

use std::sync::Arc;

use anyhow::Result;
use tokio_rustls::TlsAcceptor;

use crate::{
    config::AppConfig,
    http_proxy::run_http_proxy,
    onvif_proxy::{run_onvif2_proxy, run_onvif_event_proxy, run_onvif_proxy},
    rtsp_proxy::run_rtsp_proxy,
    tls_proxy::{build_native_tls_connector, generate_tls_server_config, run_https_proxy},
};

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
