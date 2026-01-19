# Tapo Multi-Protocol Proxy

A Rust proxy that fronts a TP-Link Tapo camera for Homebridge/HomeKit by forwarding multiple protocols (HTTPS, RTSP, ONVIF, HTTP) from local ports to the camera. It exists because newer Tapo firmware ships with legacy certificates that can break Homebridge plugins and Home Assistant. The proxy terminates TLS with a secure certificate on port 443, proxies ONVIF/HTTP, rewrites ONVIF URLs to public endpoints, and supports RTSP over TCP or UDP (with UDP relay).

## Features

- HTTPS front-end with self-signed certificate, upstream TLS via native-tls.
- RTSP proxy with URL/SDP rewrites and optional UDP relay.
- ONVIF, ONVIF2, ONVIF-EVENT, and HTTP proxying with response URL rewriting.
- Configurable upstream and public endpoints via environment variables.
- Debug logging for request/response traces and RTSP/UDP stats.

## Requirements

- Rust toolchain (stable) to build/run.
- Homebridge: set the video codec to `libx264`.
  - The default `copy` codec can fail to stream in HomeKit for some clients.
  - Snapshot works without changes, but streaming requires `libx264` in this setup.
 - Tested with Homebridge + `homebridge-tapo-camera`.

## Build

```sh
cargo build
```

## Run

There are no CLI arguments. All configuration is done via environment variables.

```sh
export UPSTREAM_HOST=10.66.0.201
export PUBLIC_HOST=10.66.0.123
export PROXY_DEBUG=1

cargo run
```

## Configuration (Environment Variables)

- `UPSTREAM_HOST` (required): camera IP/hostname the proxy connects to.
- `UPSTREAM_HTTPS_PORT` (default `443`): camera HTTPS port.
- `UPSTREAM_RTSP_PORT` (default `554`): camera RTSP port.
- `UPSTREAM_ONVIF_PORT` (default `2020`): camera ONVIF device service port.
- `UPSTREAM_HTTP_PORT` (default `8800`): camera HTTP port (if used).
- `UPSTREAM_ONVIF2_PORT` (default `1024`): camera ONVIF events port.
- `UPSTREAM_ONVIF_EVENT_PORT` (default `1025`): camera ONVIF event pull port.

- `HTTPS_LISTEN_PORT` (default `443`): local HTTPS listen port.
- `RTSP_LISTEN_PORT` (default `554`): local RTSP listen port.
- `ONVIF_LISTEN_PORT` (default `2020`): local ONVIF listen port.
- `HTTP_LISTEN_PORT` (default `8800`): local HTTP listen port.
- `ONVIF2_LISTEN_PORT` (default `1024`): local ONVIF2 listen port.
- `ONVIF_EVENT_LISTEN_PORT` (default `1025`): local ONVIF-EVENT listen port.

- `PUBLIC_HOST` (required): hostname/IP clients use to reach the proxy.
- `PUBLIC_HTTPS_PORT` (default `HTTPS_LISTEN_PORT`): public HTTPS port in rewritten URLs.
- `PUBLIC_HTTP_PORT` (default `HTTP_LISTEN_PORT`): public HTTP port in rewritten URLs.
- `PUBLIC_RTSP_PORT` (default `RTSP_LISTEN_PORT`): public RTSP port in rewritten URLs.
- `PUBLIC_ONVIF_PORT` (default `ONVIF_LISTEN_PORT`): public ONVIF port in rewritten URLs.
- `PUBLIC_ONVIF2_PORT` (default `ONVIF2_LISTEN_PORT`): public ONVIF2 port in rewritten URLs.
- `PUBLIC_ONVIF_EVENT_PORT` (default `ONVIF_EVENT_LISTEN_PORT`): public ONVIF-EVENT port in rewritten URLs.

- `PROXY_DEBUG` (default `off`): set to `1`, `true`, `yes`, or `on` for verbose logs.
- `RTSP_FORCE_TCP` (default `off`): set to `1`, `true`, `yes`, or `on` to force RTSP over TCP.

## Logs & Debugging

- Normal mode logs basic listener startup and connection errors.
- Set `PROXY_DEBUG=1` for verbose logs:
  - HTTP/ONVIF request/response summaries and body snippets.
  - ONVIF action detection and URL rewrite checks.
  - RTSP handshake, header/SDP traces, Content-Base rewrites.
  - UDP relay stats (`rtp_in`, `rtp_out`, `rtcp_in`, `rtcp_out`).

## Notes for Homebridge

- Use the proxy host/ports for all protocols (HTTPS/RTSP/ONVIF/HTTP).
- Ensure `PUBLIC_HOST` and `PUBLIC_*_PORT` match the address/ports Homebridge can reach.
- Streaming requirement: set Homebridge video codec to `libx264`.

## Troubleshooting

- If snapshots fail, check ONVIF/HTTP rewriting and `PROXY_DEBUG` logs.
- If RTSP stream does not start, verify:
  - `PUBLIC_HOST` is reachable from the Homebridge host.
  - UDP traffic is permitted if `RTSP_FORCE_TCP` is not set.
  - Homebridge uses `libx264` for video encoding.

## License

MIT (see `Cargo.toml` for details).
