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

Compatibility requirement:

- `libcodec2.so` must export `incomudon_codec2_abi_version`.
- Expected ABI value: `2026022801`.
- If ABI/symbol does not match, PWA marks Codec2 unavailable and falls back to PCM.

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

- `-directory-udp-listen :51000`
- `INCOMUDON_DIRECTORY_UDP_LISTEN=:51000`
- `-directory-psk-file /run/incomudon-directory/directory.psk`
- `INCOMUDON_DIRECTORY_PSK_FILE=/run/incomudon-directory/directory.psk`
- `-directory-key-id pwa-1` / `INCOMUDON_DIRECTORY_KEY_ID=pwa-1`
- `-directory-udp-allow-cidrs 203.0.113.10/32`
- `INCOMUDON_DIRECTORY_UDP_ALLOW_CIDRS=203.0.113.10/32`
- `-directory-relay-udp-target relay.example.com:51001`
- `INCOMUDON_DIRECTORY_RELAY_UDP_TARGET=relay.example.com:51001`
- `-codec2-lib /path/to/libcodec2.so`
- `INCOMUDON_CODEC2_LIB=/path/to/libcodec2.so`
- Web UI field: `Codec2 Library Path (server)`
- `-opus-lib /path/to/libopus.so`
- `INCOMUDON_OPUS_LIB=/path/to/libopus.so`
- Web UI field: `Opus Library Path (server)`
- `-fixed-relay host[:port]`
- `INCOMUDON_FIXED_RELAY=host[:port]`
- `-multi-max-slots 1..10`
- `INCOMUDON_MULTI_MAX_SLOTS=1..10` (default: `10`)
- `INCOMUDON_MULTI_DEFAULT_SLOTS=1..10` (default: `4`, capped by the maximum)
- `-multi-path /custom-multi-page`
- `INCOMUDON_MULTI_PATH=/custom-multi-page` (default: `<base-path>/multi`)
- `-auth-mode none|basic|oidc`
- `INCOMUDON_AUTH_MODE=none|basic|oidc`
- `-ws-token <shared-token>`
- `INCOMUDON_WS_TOKEN=<shared-token>`
- Web UI field: `WS Token` (`Advanced Settings`)
- `-basic-user <user>` / `-basic-pass <pass>`
- `INCOMUDON_BASIC_USER` / `INCOMUDON_BASIC_PASS`
- `-oidc-issuer <issuer-url>`
- `-oidc-client-id <client-id>`
- `-oidc-client-secret <client-secret>`
- `-oidc-session-secret <random-secret>`
- `-oidc-scopes openid,profile,email`
- `-oidc-redirect-url https://.../auth/callback` (optional override)
- `-oidc-session-ttl 72h` (OIDC session cookie TTL; default `72h`, set `0` to follow token expiry)
- `INCOMUDON_OIDC_ISSUER`, `INCOMUDON_OIDC_CLIENT_ID`, `INCOMUDON_OIDC_CLIENT_SECRET`
- `INCOMUDON_OIDC_SESSION_SECRET`, `INCOMUDON_OIDC_SCOPES`, `INCOMUDON_OIDC_REDIRECT_URL`, `INCOMUDON_OIDC_SESSION_TTL`

When `-codec2-lib` is not specified and uplink Codec2 is enabled, loader auto-searches
`/opt/libcodec2` and `third_party/libcodec2` (including arch subdirectories).

If Opus cannot be loaded, uplink/downlink automatically fall back to PCM.

If Codec2 cannot be loaded (missing symbol/ABI mismatch/dependency issue), uplink/downlink
Codec2 paths are disabled and PWA falls back to PCM.

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
  - Query `ws_token` overrides the `WS Token` textbox and any stored value.
  - Token received from query is cached in browser storage and reused on next launches.
  - `wss://.../ws?token=<shared-token>` is sent automatically by the web app.
- Recommended profile:
  - Minimum: `-fixed-relay` + `-auth-mode basic` (or `oidc`)
  - Stronger: `-fixed-relay` + `-auth-mode oidc` + `-ws-token`

## PSK Directory Provisioning

The PWA server can receive the Relay Server's PSK-protected UDP directory and
provision its verified channel/speaker display names plus current participant
snapshots to authenticated browser WebSocket connections. Browsers never
receive the PSK and never directly accept UDP packets.

Enable the receiver by configuring both `-directory-udp-listen` and
`-directory-psk-file`. `-directory-key-id` must match the relay's key ID and
defaults to `pwa-1`. `-directory-udp-allow-cidrs` is optional in code but
strongly recommended in production; it accepts a comma-separated CIDR list for
the relay source address.

The receiver verifies AES-256-GCM authentication before parsing a document. It
requires an authenticated expiry, rejects entries that exceed protocol limits,
rejects replays within an epoch, and keeps only a valid unexpired snapshot.
PWA screens show a provisioned name as `Name (ID)` in active talker state and
in talk start/end logs; forms still retain their numeric IDs and remain locally
configured.

Set `-directory-relay-udp-target` (or
`INCOMUDON_DIRECTORY_RELAY_UDP_TARGET`) to the Relay's directory pull listener
to enable on-demand refreshes. An authenticated browser WebSocket client can
send `{ "type": "request_directory_participants" }`; the PWA server signs a
short-lived UDP request, then forwards the Relay's refreshed `directory` and
`directory_participants` events to its WebSocket clients. The protocol carries
only `channelId`, `senderId`, `lastSeenAt`, and `talking` for each participant.

Set the PWA and relay to the same key file through a secure out-of-band channel.
Do not use a raw PSK in an environment variable, query string, browser storage,
or CSV. Allow inbound UDP only from the relay's fixed IP address, and keep the
existing HTTPS plus PWA authentication controls enabled for browser access.

## Authentication Modes

- `none`: no HTTP authentication.
- `basic`: HTTP Basic authentication on all pages/assets/WebSocket.
- `oidc`: OIDC login (Authorization Code flow) with signed session cookie.
- `oidc` session persistence can be tuned by `-oidc-session-ttl` / `INCOMUDON_OIDC_SESSION_TTL`.
- Logout button is shown in UI when `auth-mode` is `basic` or `oidc`.
- When `auth-mode` is `basic`/`oidc`, Service Worker is still registered (for PWA installability), but cache storage is disabled to avoid stale-auth issues.
- The server does not apply a Pong-response read deadline, because Android Chrome may freeze background pages long enough to miss control-frame handling. Failed server writes still close unusable sockets promptly.
- Android browsers or the OS may still close a background WebSocket. When the PWA becomes visible again after an unexpected close, it restarts its bounded reconnect sequence; this does not always mean auth expiry.

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
go run . \
  -listen :8080 \
  -fixed-relay 192.0.2.10:50000 \
  -auth-mode basic \
  -basic-user demo \
  -basic-pass change-me
```

### OIDC Example

```bash
go run . \
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

## Browser Settings Lock

`Settings Lock` is configured independently in each browser profile; it does not require a
server environment variable, cookie, or API endpoint. Enabling it stores a random salt and a
PBKDF2-SHA-256 verifier in browser local storage. The raw master password is neither sent to
nor retained by the server. Unlocking is remembered only for the current browser session.

While locked, the UI permits only transmit bitrate, microphone volume, and multi-channel
shortcut changes. Channel ID, channel password, sender ID, and transmit codec are disabled;
Advanced Settings, Cue Sounds, and Audio File TX are hidden. The saved connection settings are
not encrypted, so auto-connect continues to work without entering the master password.

This is a casual UI lock, not an access-control boundary. Anyone with browser-profile access or
developer tools can inspect or remove browser storage. Use HTTP Basic or OIDC authentication
when relay or configuration access must be protected from untrusted users.

## Browser Background Audio

The browser client avoids `window.setInterval(20)` for microphone transmission.
Microphone frames are emitted by `mic-capture-worklet.js` and sent immediately
when the WebSocket is writable. If `WebSocket.bufferedAmount` reaches 1 KiB,
new uplink frames are dropped rather than replayed late. This keeps PTT audio
real-time when the network is congested.

Audio-file TX is paced by the AudioContext render clock in
`audio-tx-pacer-worklet.js`; it sends one 20 ms source frame at a time and skips
frames that became stale while the page main thread was delayed. A browser
without AudioWorklet uses a `window.setInterval` compatibility fallback.

Audio-file TX is converted to **8 kHz mono PCM** before it enters the selected
PCM, Codec2, or Opus transport. This is required by the current 160-sample/
20 ms relay frame contract. Consequently, source content above approximately
4 kHz cannot be preserved; a high Opus bitrate improves coding artifacts but
cannot turn this narrowband protocol into full-band audio. The browser decodes
the file directly into an 8 kHz `OfflineAudioContext` before mono rendering, so
the source does not first pass through the default 44.1/48 kHz AudioContext and
an unnecessary second resample. Full-band source playback would require a
versioned relay/native-client protocol change, including an explicit
sample-rate negotiation.

PCM receive audio uses the continuous `pcm-playback-worklet.js` stream on
Chrome/Edge desktop and Android. It owns a bounded jitter buffer and a
windowed-sinc resampler from the relay's 8 kHz PCM stream to the AudioContext
sample rate. Old buffered receive samples are discarded rather than played
seconds late.

For diagnostics, open the client with `?audio_debug=1`, or run this in the
browser console:

```js
window.__incomudonAudioDebug.setEnabled(true)
window.__incomudonAudioDebug.snapshot()
```

Debug output is limited to lifecycle events, frame-gap summaries, backpressure
frames, and playback underruns. It reports `visibilityState`, focus state,
WebSocket state/buffered amount, AudioContext state/current time, and stream
buffer data.

For a per-session packet monitor, append `?packet_debug=1` to either the
single-channel page or the multi-channel page URL. The multi-channel console
shows one monitor per slot. It updates once per second and reports browser
TX/RX frame timing, browser and server WebSocket backpressure, relay UDP
packet counters, decode/mix queues, active sender counters, and playback
jitter-buffer underruns. The monitor contains aggregate counters only: it
does not expose packet payloads, keys, passwords, or relay credentials. Its
`Reset counters` control starts a fresh measurement without disconnecting.

Browser and OS scheduling is not fully under application control. Desktop
Chrome/Edge normally keep an active AudioContext and WebSocket functioning when
focus moves to another window. A hidden/minimized page or OS power management
can still suspend the AudioContext or defer WebSocket/main-thread delivery for
an extended period; no PWA can guarantee uninterrupted real-time audio in that
case. The client resumes the output context only when it becomes visible again
and does not reconnect merely because focus changed.

On the multi-channel page, a `window.blur` event deliberately releases only
manual hold-to-talk shortcuts/buttons. This prevents a missing `keyup` from
leaving a transmitter stuck on. Audio-file TX is not part of that manual PTT
set and continues while the page is unfocused.

## Multi-Channel Console

The multi-channel page opens independent relay sessions in one browser window and is
intended primarily for desktop Chrome or Edge in landscape orientation. The layout
uses a responsive grid and collapses to a single column on narrower screens.

- URL: `<base-path>/multi` by default. For example, `-base-path /incomudon`
  exposes it at `/incomudon/multi`.
- `INCOMUDON_MULTI_MAX_SLOTS` controls the maximum number of slots a browser can add;
  it defaults to `10` and accepts values from `1` through `10`.
- `INCOMUDON_MULTI_DEFAULT_SLOTS` controls the initial slot count for a browser without
  a locally saved slot count. It defaults to `4` and is capped by the configured maximum.
- `INCOMUDON_MULTI_PATH` changes the URL. A relative value is placed under the
  configured base path; an absolute value begins with `/`.
- Each slot has isolated connection settings, cue settings, and browser-saved local
  cue/audio-TX files. Use the `Slot Settings and Cue Sounds` tab panel to select a
  slot, edit its settings, and use that slot's Connect button.
- The language selector uses the same English/Japanese preference as the single-channel
  page. Changing it reloads the multi page and all slot settings frames in that language.
- The unified Events console receives logs from every slot. Each line is prefixed with
  its local time and source, for example `[12:34:56][Slot 2]`; multi-page events use
  the `Main` source label.
- Slot PTT shortcuts default to `1` through `9`, then `0` for slot 10. Shortcut
  editing is locked by default; use `Edit Shortcuts` to unlock it temporarily.
  PTT transmission is disabled while editing, and `Esc`, clicking elsewhere, or
  30 seconds of inactivity locks the controls again.
- Select the slots that should receive a simultaneous transmission with
  `Broadcast target`. The broadcast shortcut defaults to `Shift+0` and can be
  changed during shortcut editing.
- After a form selection is committed, the page returns keyboard focus to the
  main area so PTT shortcuts are available again. Text fields keep their normal
  typing focus until they are committed or focus is moved away.
- The page captures the microphone once and duplicates 8 kHz PCM frames only to
  the currently pressed slot PTTs. This avoids multiple browser microphone captures
  during simultaneous transmission. The active slot's Mic Volume setting is used
  while transmitting to multiple slots.

The remote-talker strip and each slot header show channel and sender/talker IDs from
the relay's talker notifications. A slot only appears as receiving when its active
speaker is not the slot's own sender ID.

## Cue Sounds (Browser)

Browser cue sounds equivalent to native client are available:

- `PTT ON`: `web/sfx/ptt_on.wav`
- `PTT OFF`: `web/sfx/ptt_off.wav`
- `Carrier Sense`: `web/sfx/carrier_sense.wav`

Default files are copied from native client assets (`assets/sfx/*.wav`).

In UI (`Cue Sounds` section), each cue can be:

- enabled/disabled
- changed by URL (`Audio URL`)
- changed by a local file, stored in browser IndexedDB and restored after restart
- tested and reset to default

Cue settings are stored in browser `localStorage`. Selected local cue files and
`Audio File TX` slot files are stored separately in IndexedDB for the same
browser origin. The storage limits are 20 MiB for all cue files, 100 MiB for
all `Audio File TX` files, and 120 MiB combined. Use `Clear Saved Files` to
remove every locally stored cue and TX file; browser site-data deletion or
private browsing can also remove them.

## UI Localization

- Supported UI languages: English (`en`) and Japanese (`ja`)
- Default language: browser locale (`navigator.languages` / `navigator.language`)
- Fallback: if matching locale file is missing, UI falls back to English
- Language can be switched from the top-right language selector
- Locale files:
  - `web/locales/en.json`
  - `web/locales/ja.json`

## Startup Query Overrides

The browser UI supports startup-time query overrides for controlled launch links.

- Supported parameters:
  - `ws_token` or `token`
  - `channel_id`, `channelId`, or `channel`
  - `password`, `pass`, or `pw`
  - `tx_codec`, `txCodec`, or `codec`
- Supported `tx_codec` values:
  - `pcm`
  - `codec2`
  - `opus`
- Override priority:
  - URL query
  - saved browser settings (`localStorage`)
  - built-in defaults
- Applied behavior:
  - Query values are copied into the UI on startup.
  - After startup reflection completes, the page URL is rewritten.
  - `ws_token` and the safe diagnostic flag `packet_debug=1` are kept in the
    rewritten URL.
  - `channel_id`, `password`, and `tx_codec` are removed from the address bar after startup.
- Notes:
  - `password` from query is still visible to the browser/history/proxy while the initial request is processed. Use it only for trusted/internal launch flows.
  - When `-fixed-relay` is enabled, relay destination still follows the server-fixed value even if other startup query overrides are used.

### CLI Examples

```bash
go run . -listen :8080 -codec2-lib /opt/libcodec2/linux-x86_64/libcodec2.so
```

```bash
go run . -listen :8080 -fixed-relay 192.0.2.10:50000 -ws-token change-me_yMT8rKy26FsPoHm6yN9
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
go run . -listen :8080 -base-path /
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
## Docker Compose

compose.yaml manages the standalone PWA service. It builds the image, starts it
with restart policy unless-stopped, and mounts user-provided Codec2/Opus library
directories read-only.

1. Create the local configuration file:

~~~bash
cp .env.example .env
~~~

2. Edit .env and set at least INCOMUDON_FIXED_RELAY for a public deployment.
   Set INCOMUDON_AUTH_MODE, authentication settings, and INCOMUDON_WS_TOKEN
   as required.

3. Build and start:

~~~bash
docker compose up -d --build
~~~

4. Check service status and logs:

~~~bash
docker compose ps
docker compose logs -f pwa-client
~~~

5. Apply configuration or dynamic library changes:

~~~bash
docker compose up -d --build
~~~

Use docker compose restart pwa-client when only a mounted libcodec2.so or
libopus.so was replaced. Stop and remove the service with:

~~~bash
docker compose down
~~~

PWA_HOST_PORT controls the host-side port and PWA_LISTEN_PORT controls the
container listener; both default to 50001. INCOMUDON_BASE_PATH defaults to /.
INCOMUDON_MULTI_MAX_SLOTS defaults to 10 and limits how many slots a browser can add.
INCOMUDON_MULTI_DEFAULT_SLOTS defaults to 4 and controls the initial slot count for a
browser without saved multi-page controls; it is capped by the configured maximum.
INCOMUDON_MULTI_PATH defaults to the base path plus /multi.
For HTTPS/reverse-proxy deployment, use the existing docker-compose.nginx.yml
configuration instead of exposing this standalone service directly to the Internet.

Place optional dynamic libraries before starting Compose:

- third_party/libcodec2/.../libcodec2.so is mounted at /opt/libcodec2.
- third_party/libopus/.../libopus.so is mounted at /opt/libopus.

Keep .env private because it can contain authentication secrets and shared tokens.

When directory provisioning is enabled, Compose mounts `./directory` read-only at
`/run/incomudon-directory` and publishes `PWA_DIRECTORY_UDP_HOST_PORT` (default
`51000`) as UDP. Set `INCOMUDON_DIRECTORY_UDP_LISTEN=:51000`,
`INCOMUDON_DIRECTORY_PSK_FILE=/run/incomudon-directory/directory.psk`, and a
narrow `INCOMUDON_DIRECTORY_UDP_ALLOW_CIDRS`. To allow authenticated immediate
participant refreshes, also set `INCOMUDON_DIRECTORY_RELAY_UDP_TARGET` to the
Relay's separate directory listener, for example `192.168.1.10:51001`. Keep
`directory/` private; it is ignored by Git.
