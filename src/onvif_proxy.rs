use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};

use crate::{config::AppConfig, http_proxy::handle_http_like};

pub async fn run_onvif_proxy(cfg: AppConfig) -> Result<()> {
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

pub async fn run_onvif2_proxy(cfg: AppConfig) -> Result<()> {
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

pub async fn run_onvif_event_proxy(cfg: AppConfig) -> Result<()> {
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
