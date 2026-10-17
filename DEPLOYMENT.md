# Public-demo deployment runbook

This document is preparation only. **Do not point public DNS or production traffic at the current app until the hardening branch has been reviewed, committed, and tested on the target host.** This branch does not change server configuration or deploy anything.

**Data-rights gate:** public mode can serve responses from many third-party market-data and news providers, including (but not limited to) Yahoo Finance, Coinbase, Kraken, Binance, Nasdaq and RSS/news sources. Do not expose any provider's feed until the applicable terms and any required redistribution permissions have been reviewed and confirmed, or that feed is removed/replaced with an appropriately licensed source. Passing tests and this repository's licence do not grant data rights.

## Public-demo contract

Public mode is opt-in and should be started with an explicit host allowlist:

```bash
PUBLIC_DEMO=1 \
PUBLIC_HOST=quant.sisengai.com \
HOST=127.0.0.1 \
PORT=3777 \
PUBLIC_RATE_MAX=60 \
PUBLIC_RATE_WINDOW_MS=60000 \
PUBLIC_CACHE_TTL_MS=5000 \
PUBLIC_CACHE_MAX=128 \
node server.js
```

The IP-bucket map is capped at 10,000 entries by default; set `PUBLIC_RATE_MAX_KEYS` to tune it (1–100,000). When full, the oldest bucket is evicted before a new client bucket is added.

`PUBLIC_DEMO=1` forces the Node server to bind to `127.0.0.1`, even if `HOST` is accidentally set to `0.0.0.0`. Requests must carry exactly `Host: quant.sisengai.com` (an optional port is ignored for comparison); `X-Forwarded-Host` is not trusted.

The public process exposes only read-only market-data routes and bounded `POST /api/scan`. It denies state, alerts/SSE, webhooks, custom JavaScript, PTQ, probe, and shutdown routes. Guest preferences are kept in each visitor's browser `localStorage`; the public process does not import the local alert/store/PTQ modules or write shared JSON state.

## Preflight without deployment

Run from a clean checkout on the target Node 18+ machine, but do not change the active service or DNS:

```bash
node --version
npm test
PUBLIC_DEMO=1 PUBLIC_HOST=quant.sisengai.com QT_OFFLINE=1 PORT=3777 node server.js
```

Verify from another terminal with the configured `Host` header:

```bash
curl -fsS -H 'Host: quant.sisengai.com' http://127.0.0.1:3777/api/health
curl -i -H 'Host: localhost' http://127.0.0.1:3777/api/health   # must be 403
```

Stop the foreground process with `Ctrl-C`. Do not use the public mode process as the normal local single-user service; normal local mode continues to use the JSON store, alerts, custom indicators, PTQ, and `/api/shutdown`.

## Caddy example (review before enabling)

The Node port remains loopback-only. Caddy terminates TLS and proxies the public hostname:

```caddyfile
quant.sisengai.com {
    encode gzip

    header {
        -Server
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "no-referrer"
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
    }

    reverse_proxy 127.0.0.1:3777 {
        # Preserve only the configured public host.
        header_up Host {host}
        # Overwrite, rather than trust, client-supplied identity headers.
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
    }
}
```

The app trusts `X-Forwarded-For`/`X-Real-IP` only when the TCP peer is loopback, which is the expected Caddy-to-Node path. Keep the Node port firewalled from the internet. Do not put a second untrusted proxy in front of Caddy without reviewing its forwarded-header behavior.

Before enabling the site, confirm:

- `quant.sisengai.com` resolves to the intended host and Caddy has a valid certificate.
- Caddy can reach `127.0.0.1:3777`, but the public network cannot reach port 3777 directly.
- A wrong `Host` returns 403 through both Caddy and the loopback port.
- Caddy does not pass an attacker-controlled `X-Forwarded-For` unchanged.
- Only the intended public-demo environment is loaded by the service.

## Service, logs, and rollback

Use a dedicated unprivileged service account and an absolute checkout path. Example systemd unit to review, not to install automatically:

```ini
[Unit]
Description=Quant Terminal public demo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=quant-terminal
WorkingDirectory=/srv/quant-terminal
Environment=PUBLIC_DEMO=1
Environment=PUBLIC_HOST=quant.sisengai.com
Environment=HOST=127.0.0.1
Environment=PORT=3777
Environment=PUBLIC_RATE_MAX=60
Environment=PUBLIC_RATE_WINDOW_MS=60000
Environment=PUBLIC_CACHE_TTL_MS=5000
Environment=PUBLIC_CACHE_MAX=128
ExecStart=/usr/bin/node /srv/quant-terminal/server.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/srv/quant-terminal/data

[Install]
WantedBy=multi-user.target
```

Public mode should not need `data/` writes; keep the `ReadWritePaths` line only if the chosen service setup requires it, and prefer a read-only filesystem policy after verification. Store environment values in the service manager, not in a committed `.env` file.

Operational commands after an approved installation:

```bash
systemctl status quant-terminal
journalctl -u quant-terminal -f
systemctl restart quant-terminal
```

For rollback, stop the service, restore the previously reviewed checkout or release, verify the old commit's tests, then restart. If the public behavior is uncertain, stop the Node service first and leave Caddy serving an explicit maintenance response; do not point traffic at an unreviewed working tree.

## Limits and provider load

Public-mode limits are intentionally conservative and can be adjusted through environment variables within the code's bounds:

- In-memory per-client API rate limit: 60 requests per 60 seconds by default (`PUBLIC_RATE_MAX`, `PUBLIC_RATE_WINDOW_MS`).
- Bounded response cache for public GET market routes: 5 seconds and 128 entries by default (`PUBLIC_CACHE_TTL_MS`, `PUBLIC_CACHE_MAX`), with a response-size cap.
- Public candles are clamped to 1,000 bars; quotes are capped at 20 symbols per request and 12 requests / 120 symbols per client window by default.
- Public scans accept at most 20 symbols, 5 rules, 20 built-in indicator definitions, and a 128 KiB JSON body; unknown indicators/parameters and non-finite or out-of-range values are rejected.
- URLs are capped at 8 KiB. Existing provider modules also have bounded in-memory caches and upstream fallbacks.

These controls reduce accidental upstream load; they are not DDoS protection and free providers can still return 429s, change behavior, or impose undocumented limits. Monitor provider errors and latency before increasing limits.

## Exact deployment gate

Do not enable Caddy, change DNS, or expose public traffic until **all** of these are true:

1. Parent review accepts the uncommitted diff on `hardening/sisengai-public-demo` and creates the production commit from the reviewed files.
2. `npm test` passes on the reviewed commit with the full suite, including the public-demo integration tests.
3. A target-host preflight starts with `PUBLIC_DEMO=1`, `PUBLIC_HOST=quant.sisengai.com`, and `HOST=127.0.0.1`; the configured Host succeeds, `Host: localhost` returns 403, and the Node listener is confirmed loopback-only.
4. The reviewed Caddy/systemd configuration is installed separately, with TLS, forwarded-header overwrite, firewalling of port 3777, service logs, and rollback ownership confirmed.
5. Parent explicitly approves the DNS/proxy cutover after checking the health response and denied-route checks through Caddy.

Until then, the deployment status is **blocked by review and explicit production approval**, not by this local implementation. This branch has not changed DNS, Caddy, systemd, firewall rules, the live site, or public traffic.

## Risks and non-goals

- Public demo mode is anonymous and has no account isolation or user identity. It is deliberately read-only at the server boundary.
- Browser `localStorage` is per browser profile and is not a backup, sync mechanism, or security boundary for secrets. Do not add credentials or private data to the public UI.
- Market data is supplied by free third-party feeds and may be delayed, incomplete, unavailable, or inaccurate. This is not financial advice.
- A reverse proxy, TLS certificate, firewall, service permissions, and DNS can still be misconfigured. Validate each independently.
- Do not enable public mode with `HOST=0.0.0.0`, expose the Node port, add authentication assumptions to the current routes, or re-enable alerts/webhooks/custom code/PTQ without a separate authenticated multi-user design.
