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

- `UPSTREAM_HOST` (required)
- `UPSTREAM_HTTPS_PORT` (default `443`)
- `UPSTREAM_RTSP_PORT` (default `554`)
- `UPSTREAM_ONVIF_PORT` (default `2020`)
- `UPSTREAM_HTTP_PORT` (default `8800`)
- `UPSTREAM_ONVIF2_PORT` (default `1024`)
- `UPSTREAM_ONVIF_EVENT_PORT` (default `1025`)

- `HTTPS_LISTEN_PORT` (default `443`)
- `RTSP_LISTEN_PORT` (default `554`)
- `ONVIF_LISTEN_PORT` (default `2020`)
- `HTTP_LISTEN_PORT` (default `8800`)
- `ONVIF2_LISTEN_PORT` (default `1024`)
- `ONVIF_EVENT_LISTEN_PORT` (default `1025`)

- `PUBLIC_HOST` (default `127.0.0.1`)
- `PUBLIC_HTTPS_PORT` (default `HTTPS_LISTEN_PORT`)
- `PUBLIC_HTTP_PORT` (default `HTTP_LISTEN_PORT`)
- `PUBLIC_RTSP_PORT` (default `RTSP_LISTEN_PORT`)
- `PUBLIC_ONVIF_PORT` (default `ONVIF_LISTEN_PORT`)
- `PUBLIC_ONVIF2_PORT` (default `ONVIF2_LISTEN_PORT`)
- `PUBLIC_ONVIF_EVENT_PORT` (default `ONVIF_EVENT_LISTEN_PORT`)

- `PROXY_DEBUG` (`1`, `true`, `yes`, `on` to enable verbose logs)
- `RTSP_FORCE_TCP` (`1`, `true`, `yes`, `on` to force TCP interleaved RTSP)

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
