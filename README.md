# IncomUdon Relay PWA Client

This directory is intended to be managed as an independent package/repository.

Architecture:

`native client <-> relay server (UDP) <-> pwa_client (this app) <-> browser`

## License Scope

- `pwa_client/` is licensed under MIT: `pwa_client/LICENSE`
- Third-party notices are documented in: `pwa_client/THIRD_PARTY_NOTICES.md`

## libcodec2 Packaging

This project supports optional user-provided `libcodec2.so` placement.

- Bundle directory: `pwa_client/third_party/libcodec2/`
- Recommended file path: `pwa_client/third_party/libcodec2/linux-x86_64/libcodec2.so`
- musl example:
  - `pwa_client/third_party/libcodec2/linux-musl-x86_64/libcodec2.so`
- Raspberry Pi examples:
  - `pwa_client/third_party/libcodec2/linux-raspi-armv7l/libcodec2.so`
  - `pwa_client/third_party/libcodec2/linux-raspi-aarch64/libcodec2.so`
  - `pwa_client/third_party/libcodec2/linux-musl-armv7l/libcodec2.so`
  - `pwa_client/third_party/libcodec2/linux-musl-aarch64/libcodec2.so`

## libopus Packaging

This project supports optional `libopus.so` bundling.

- Bundle directory: `pwa_client/third_party/libopus/`
- Recommended file path: `pwa_client/third_party/libopus/linux-x86_64/libopus.so`
- musl example:
  - `pwa_client/third_party/libopus/linux-musl-x86_64/libopus.so`
- Raspberry Pi examples:
  - `pwa_client/third_party/libopus/linux-raspi-armv7l/libopus.so`
  - `pwa_client/third_party/libopus/linux-raspi-aarch64/libopus.so`
  - `pwa_client/third_party/libopus/linux-musl-armv7l/libopus.so`
  - `pwa_client/third_party/libopus/linux-musl-aarch64/libopus.so`
- Opus license text: `pwa_client/LICENSES/opus/COPYING`
- Opus patent notice links: `pwa_client/LICENSES/opus/PATENT-NOTICE.txt`

## Runtime Options

- `-codec2-lib /path/to/libcodec2.so`
- `INCOMUDON_CODEC2_LIB=/path/to/libcodec2.so`
- Web UI field: `Codec2 Library Path (server)`
- `-opus-lib /path/to/libopus.so`
- `INCOMUDON_OPUS_LIB=/path/to/libopus.so`
- Web UI field: `Opus Library Path (server)`
- `-fixed-relay host[:port]`
- `INCOMUDON_FIXED_RELAY=host[:port]`
- `-auth-mode none|basic|oidc`
- `INCOMUDON_AUTH_MODE=none|basic|oidc`
- `-ws-token <shared-token>`
- `INCOMUDON_WS_TOKEN=<shared-token>`
- `-basic-user <user>` / `-basic-pass <pass>`
- `INCOMUDON_BASIC_USER` / `INCOMUDON_BASIC_PASS`
- `-oidc-issuer <issuer-url>`
- `-oidc-client-id <client-id>`
- `-oidc-client-secret <client-secret>`
- `-oidc-session-secret <random-secret>`
- `-oidc-scopes openid,profile,email`
- `-oidc-redirect-url https://.../auth/callback` (optional override)
- `-oidc-session-ttl 12h` (OIDC session cookie TTL; default `12h`, set `0` to follow token expiry)
- `INCOMUDON_OIDC_ISSUER`, `INCOMUDON_OIDC_CLIENT_ID`, `INCOMUDON_OIDC_CLIENT_SECRET`
- `INCOMUDON_OIDC_SESSION_SECRET`, `INCOMUDON_OIDC_SCOPES`, `INCOMUDON_OIDC_REDIRECT_URL`, `INCOMUDON_OIDC_SESSION_TTL`

When `-codec2-lib` is not specified and uplink Codec2 is enabled, loader auto-searches
`/opt/libcodec2` and `third_party/libcodec2` (including arch subdirectories).

If Opus cannot be loaded, uplink/downlink automatically fall back to PCM.

Browser Opus requires `WebCodecs AudioEncoder` (uplink) and `WebCodecs AudioDecoder` (downlink).

## Security Hardening (Public Deployment)

- For public deployment, enabling both `-fixed-relay` and an authentication mode (`-auth-mode basic|oidc`) is **strongly recommended**.
- Why `-fixed-relay` is important:
  - Without fixed relay, external users can set arbitrary `Relay Host/Port` and force server-side UDP access attempts.
  - This can be abused for internal network reachability probing (SSRF-like behavior over UDP).
  - `-fixed-relay` removes user control of relay destination and limits egress target.
- Why authentication is important:
  - Without authentication, anyone who can access the PWA endpoint can connect and use relay functions.
  - This allows unauthorized traffic injection, channel abuse, and avoidable resource consumption.
  - `-auth-mode basic|oidc` limits access to authorized users.
- `-fixed-relay` behavior:
  - Browser-provided `Relay Host/Port` is ignored.
  - UI Relay fields are locked to server-fixed values.
- `-ws-token` behavior:
  - Requires a shared token on every WebSocket connection (additional gate).
  - Browser side can pass token via URL query:
    - `https://your-host.example/?ws_token=<shared-token>`
    - If `-base-path /incomudon/` is used, include trailing slash:
      - `https://your-host.example/incomudon/?ws_token=<shared-token>`
  - Token received from query is cached in browser storage and reused on next launches.
  - `wss://.../ws?token=<shared-token>` is sent automatically by the web app.
- Recommended profile:
  - Minimum: `-fixed-relay` + `-auth-mode basic` (or `oidc`)
  - Stronger: `-fixed-relay` + `-auth-mode oidc` + `-ws-token`

## Authentication Modes

- `none`: no HTTP authentication.
- `basic`: HTTP Basic authentication on all pages/assets/WebSocket.
- `oidc`: OIDC login (Authorization Code flow) with signed session cookie.
- `oidc` session persistence can be tuned by `-oidc-session-ttl` / `INCOMUDON_OIDC_SESSION_TTL`.
- Logout button is shown in UI when `auth-mode` is `basic` or `oidc`.
- When `auth-mode` is `basic`/`oidc`, Service Worker is still registered (for PWA installability), but cache storage is disabled to avoid stale-auth issues.
- On mobile browsers, WebSocket can still be closed when app is backgrounded; this does not always mean auth expiry.

### Authentication Methods Summary

| Method | Option | Protects | Pros | Notes |
| --- | --- | --- | --- | --- |
| None | `-auth-mode none` | none | easiest setup | not recommended for public exposure |
| HTTP Basic | `-auth-mode basic` + `-basic-user/-basic-pass` | pages, assets, WebSocket | simple, widely supported | credential distribution/rotation is manual |
| OIDC | `-auth-mode oidc` + OIDC settings | pages, assets, WebSocket | centralized SSO, user lifecycle control | requires IdP/client setup |
| WebSocket token (additional gate) | `-ws-token` | WebSocket handshake | easy extra barrier | shared secret model; combine with Basic/OIDC |

## API Specifications

- OpenAPI (HTTP endpoints + WebSocket handshake):
  - `pwa_client/docs/openapi.yaml`
- AsyncAPI (WebSocket messages, JSON commands/events, binary audio frames):
  - `pwa_client/docs/asyncapi.yaml`

Scope split:

- `openapi.yaml` covers HTTP routes (`/auth/*`, `/ws` handshake, `/` entry).
- `asyncapi.yaml` covers runtime WebSocket payload protocol (`connect/disconnect/ptt/...` and PCM/Opus frame types).

### Basic Example

```bash
go run ./main.go \
  -listen :8080 \
  -fixed-relay 192.0.2.10:50000 \
  -auth-mode basic \
  -basic-user demo \
  -basic-pass change-me
```

### OIDC Example

```bash
go run ./main.go \
  -listen :8080 \
  -base-path /incomudon/ \
  -fixed-relay 192.0.2.10:50000 \
  -auth-mode oidc \
  -oidc-issuer https://accounts.example.com/realms/demo \
  -oidc-client-id incomudon-pwa \
  -oidc-client-secret change-me \
  -oidc-session-secret replace-with-long-random-string \
  -oidc-session-ttl 24h
```

Notes:

- Register callback URL in your IdP as:
  - no base path: `https://<host>/auth/callback`
  - with `-base-path /incomudon/`: `https://<host>/incomudon/auth/callback`

## Cue Sounds (Browser)

Browser cue sounds equivalent to native client are available:

- `PTT ON`: `web/sfx/ptt_on.wav`
- `PTT OFF`: `web/sfx/ptt_off.wav`
- `Carrier Sense`: `web/sfx/carrier_sense.wav`

Default files are copied from native client assets (`assets/sfx/*.wav`).

In UI (`Cue Sounds` section), each cue can be:

- enabled/disabled
- changed by URL (`Audio URL`)
- changed by local file (`Local File`, session only)
- tested and reset to default

Cue settings are stored in browser `localStorage`.

## UI Localization

- Supported UI languages: English (`en`) and Japanese (`ja`)
- Default language: browser locale (`navigator.languages` / `navigator.language`)
- Fallback: if matching locale file is missing, UI falls back to English
- Language can be switched from the top-right language selector
- Locale files:
  - `web/locales/en.json`
  - `web/locales/ja.json`

### CLI Examples

```bash
go run ./main.go -listen :8080 -codec2-lib /opt/libcodec2/linux-x86_64/libcodec2.so
```

```bash
go run ./main.go -listen :8080 -fixed-relay 192.0.2.10:50000 -ws-token change-me_yMT8rKy26FsPoHm6yN9
```

```bash
docker run --rm -p 8080:8080 \
  -v $(pwd)/third_party/libcodec2:/opt/libcodec2:ro \
  incomudon-pwa-client \
  -listen :8080 \
  -codec2-lib /opt/libcodec2/linux-x86_64/libcodec2.so
```

## Build

```bash
go run ./main.go -listen :8080 -base-path /
```

```bash
docker build -t incomudon-pwa-client . --no-cache
docker run --rm -p 8080:8080 incomudon-pwa-client -listen :8080 -fixed-relay <Server-IP-address_or_hostname>:<Server-port> -ws-token <change-me> -base-path /
```

If you place `libcodec2.so` under `third_party/libcodec2/`, it is copied into image at `/opt/libcodec2`.
If you place `libopus.so` under `third_party/libopus/`, it is copied into image at `/opt/libopus`.

### Opus Library Compatibility Note

`pwa_client` runtime image is Alpine (musl). If you provide your own
`libopus.so`, it must be ABI-compatible with musl. A glibc-built library can
fail with errors like `__memcpy_chk: symbol not found`.

The Docker image also installs Alpine's `libopus` package, so fallback
`libopus.so.0` is available even when bundled `/opt/libopus/.../libopus.so`
is incompatible.

## Browser Opus (Uplink/Downlink)

- `Browser Codec`: `pcm` / `opus (optional)` (shared for uplink/downlink)
- `TX Codec`: `pcm` / `codec2` / `opus` (PWA -> relay server)
- `Transmit Bitrate`:
  - For `codec2`/`pcm`: `450`, `700`, `1600`, `2400`, `3200`
  - For `opus`: `6000`, `8000`, `12000`, `16000`, `20000`, `64000`, `96000`, `128000`
- `Network QoS (DSCP EF)`: `On` / `Off` (default `On`)
- `TX FEC (RS 2-loss)`: `On` / `Off` (default `On`)
- `TX Codec` options are automatically filtered by server runtime library availability.
  - `codec2` is shown only when `libcodec2` is available.
  - `opus` is shown only when `libopus` is available.

Behavior:

- If browser Opus encoder/decoder is unavailable, browser side falls back to `pcm`.
- If server-side `libopus` cannot be loaded, `pwa_client` falls back to `pcm`.
- If `TX Codec=opus` and `Browser Codec=opus`, browser uplink Opus bitrate is aligned to `Transmit Bitrate`.
- In that same mode, browser Opus uplink packets are passed through to relay uplink (no server-side Opus re-encode).
- When `TX FEC` is enabled, parity packets (`PKT_FEC`) are transmitted for uplink audio frames.
- QoS `On` requests DSCP EF marking on the server-side UDP socket (Linux runtime).
  - If the OS/network does not allow it, a warning is logged and communication continues.

## Nginx Reverse Proxy (HTTPS)

`deploy/nginx/` includes an HTTPS reverse proxy config for browser microphone/WebSocket use.

1. Place certificates:

```bash
cp /path/to/fullchain.pem deploy/nginx/certs/fullchain.pem
cp /path/to/privkey.pem deploy/nginx/certs/privkey.pem
```

2. Start `pwa_client` + `nginx`:

```bash
docker compose -f docker-compose.nginx.yml up -d --build
```

3. Access:

```text
https://<your-hostname-or-ip>/
```

Files:

- `pwa_client/docker-compose.nginx.yml`
- `pwa_client/deploy/nginx/nginx.conf`
- `pwa_client/deploy/nginx/conf.d/incomudon-pwa.conf`

### Binary Nginx Config Example

If you run Nginx as a host-installed binary (not Docker), use a config like this:

```nginx
upstream incomudon_pwa_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    location /ws {
        proxy_pass http://incomudon_pwa_backend;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location / {
        proxy_pass http://incomudon_pwa_backend;
        proxy_read_timeout 60s;
    }
}
```

Start `pwa_client` first, then reload Nginx:

```bash
./incomudon-pwa-client -listen :8080 -base-path /
sudo nginx -t
sudo systemctl reload nginx
```
