# TaProxy

A multi-protocol proxy server designed for TP-Link Tapo cameras, written in Rust. TaProxy intercepts and rewrites camera traffic to enable remote access and URL rewriting for HTTPS, RTSP, ONVIF, and HTTP protocols.

## Features

- **HTTPS Proxy**: Terminates TLS connections from clients and establishes secure connections to upstream camera servers
- **RTSP Proxy**: Proxies Real-Time Streaming Protocol traffic for video streaming
- **ONVIF Proxy**: Handles ONVIF (Open Network Video Interface Forum) protocol communications on multiple ports
- **HTTP Proxy**: Proxies HTTP traffic with intelligent URL rewriting in responses
- **URL Rewriting**: Automatically rewrites upstream camera URLs to public-facing endpoints
- **Self-Signed Certificate Generation**: Generates self-signed TLS certificates on startup
- **Debug Logging**: Optional debug mode for troubleshooting

## Installation

### Prerequisites

- Rust 1.70+ (edition 2024)
- Cargo package manager

### Building from Source

```bash
git clone https://github.com/kanik0/TaProxy.git
cd TaProxy
cargo build --release
```

The compiled binary will be available at `target/release/tapofix`.

## Configuration

TaProxy is configured entirely through environment variables:

### Listen Ports

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTPS_LISTEN_PORT` | `443` | Port for incoming HTTPS connections |
| `RTSP_LISTEN_PORT` | `554` | Port for incoming RTSP connections |
| `ONVIF_LISTEN_PORT` | `2020` | Port for incoming ONVIF connections |
| `HTTP_LISTEN_PORT` | `8800` | Port for incoming HTTP connections |
| `ONVIF2_LISTEN_PORT` | `1024` | Port for secondary ONVIF connections |

### Upstream Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_HOST` | `10.66.0.201` | IP address or hostname of the upstream camera |
| `UPSTREAM_HTTPS_PORT` | `443` | HTTPS port on the upstream camera |
| `UPSTREAM_RTSP_PORT` | `554` | RTSP port on the upstream camera |
| `UPSTREAM_ONVIF_PORT` | `2020` | ONVIF port on the upstream camera |
| `UPSTREAM_HTTP_PORT` | `8800` | HTTP port on the upstream camera |
| `UPSTREAM_ONVIF2_PORT` | `1024` | Secondary ONVIF port on the upstream camera |

### Public-Facing Configuration

These settings control how URLs are rewritten in responses:

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLIC_HOST` | `127.0.0.1` | Public hostname or IP address |
| `PUBLIC_HTTP_PORT` | Same as `HTTP_LISTEN_PORT` | Public HTTP port |
| `PUBLIC_RTSP_PORT` | Same as `RTSP_LISTEN_PORT` | Public RTSP port |
| `PUBLIC_ONVIF_PORT` | Same as `ONVIF_LISTEN_PORT` | Public ONVIF port |
| `PUBLIC_ONVIF2_PORT` | Same as `ONVIF2_LISTEN_PORT` | Public secondary ONVIF port |

### Debug Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_DEBUG` | `false` | Enable debug logging (accepts: `1`, `true`, `yes`, `on`) |

## Usage

### Basic Usage

Run with default settings (proxying to `10.66.0.201`):

```bash
./target/release/tapofix
```

### Custom Configuration

```bash
UPSTREAM_HOST=192.168.1.100 \
PUBLIC_HOST=example.com \
HTTPS_LISTEN_PORT=8443 \
PROXY_DEBUG=true \
./target/release/tapofix
```

### Docker Example (if containerized)

```bash
docker run -d \
  -e UPSTREAM_HOST=192.168.1.100 \
  -e PUBLIC_HOST=example.com \
  -p 443:443 \
  -p 554:554 \
  -p 2020:2020 \
  -p 8800:8800 \
  -p 1024:1024 \
  taproxy
```

## How It Works

1. **HTTPS Proxy**: 
   - Accepts TLS connections from clients using a self-generated certificate
   - Establishes TLS connections to the upstream camera (accepts invalid certificates)
   - Bidirectionally copies traffic between client and upstream

2. **HTTP Proxy with URL Rewriting**:
   - Intercepts HTTP requests and forwards them to the upstream camera
   - Parses HTTP responses and rewrites embedded URLs
   - Replaces upstream camera URLs with public-facing URLs
   - Updates `Content-Length` headers after rewriting

3. **RTSP/ONVIF Proxies**:
   - Simple TCP proxy that bidirectionally forwards traffic
   - No packet inspection or modification

## Security Considerations

- The proxy accepts **invalid TLS certificates** from upstream servers (useful for self-signed camera certificates)
- A **self-signed certificate** is generated on startup for the HTTPS proxy
- For production use, consider:
  - Using proper TLS certificates (e.g., Let's Encrypt)
  - Implementing proper certificate validation
  - Adding authentication/authorization
  - Running behind a reverse proxy with proper security headers

## License

Please check the repository for license information.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For issues, questions, or feature requests, please open an issue on the [GitHub repository](https://github.com/kanik0/TaProxy).
