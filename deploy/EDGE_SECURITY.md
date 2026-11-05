# Edge and HTTP Ingress Security

Sub2API supports long-lived SSE and WebSocket requests. Protect the request
ingress without imposing a response `WriteTimeout`: a write deadline would
terminate healthy long generations and streams.

## Application defaults

- `server.max_header_bytes: 65536` limits HTTP/1 request headers to 64 KiB;
  Go maps it to the corresponding HTTP/2 header-list limit.
- `server.read_header_timeout: 10` bounds slow-header attacks. It does not
  limit request processing or response streaming.
- `server.max_request_body_size: 268435456` is the absolute 256 MiB safety net.
- `server.api_max_request_body_size: 1048576` caps request bodies of every
  non-gateway route (`/api/v1/**`, the setup wizard, `/api/event_logging/batch`)
  at 1 MiB. A larger `Content-Length` is rejected with 413 before any byte of
  the body is read; chunked bodies are read at most 1 MiB + 1 byte and then
  rejected with 413. `server.api_read_timeout: 30` bounds how long reading that
  body may take (408 on timeout). The deadline is cleared as soon as the body
  has been read, so long handlers and SSE responses are unaffected. Gateway
  routes are not covered and keep the gateway limits below and no read timeout.
- These admin endpoints legitimately need larger bodies and are exempt from the
  1 MiB cap; they use `server.max_request_body_size` and
  `server.api_large_body_read_timeout: 600`:
  `PUT /api/v1/admin/settings`, `POST /api/v1/admin/accounts/data`,
  `POST /api/v1/admin/accounts/batch`,
  `POST /api/v1/admin/accounts/batch-update-credentials`,
  `POST /api/v1/admin/proxies/data`, `POST /api/v1/admin/proxies/batch`,
  `POST /api/v1/admin/plugins/upload`, `PUT /api/v1/admin/plugins/:id/config`.
  If your reverse proxy sets `client_max_body_size`, keep it at least as large
  as what these endpoints need (or scope a larger value to these paths only).
- `gateway.max_body_size: 268435456` remains available to multimodal, Gemini,
  image, video, and batch-image endpoints.
- `gateway.text_max_body_size: 33554432` limits the known pure-text
  `/embeddings` and `/alpha/search` endpoints to 32 MiB.
- H2C defaults to 50 concurrent streams per connection, a 2 MiB connection
  upload window, and a 512 KiB stream upload window.
- Invalid credential abuse is limited in process by trusted client IP (IPv6
  `/64`): 120 failures per 60 seconds followed by a 60-second block. This is a
  per-instance safety net; multi-instance enforcement still belongs at the
  load balancer, CDN, or WAF.

Do not add a single application-wide request semaphore: an SSE request may
legitimately occupy it for many minutes. Apply connection and unauthenticated
request controls at the edge; authenticated user/API-key concurrency remains
the application's responsibility.

## Trusted client IPs

Sub2API resolves the client IP in exactly one place (`ip.ClientIP`). API-key
IP allow/deny lists, rate limiting, session binding, audit logs, access logs
and payment requests all use that result.

* **Default: forwarded headers are not trusted.** `server.trusted_proxies`
  defaults to an empty list. Unless the direct TCP peer is inside one of the
  listed CIDRs/IPs, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` and any
  custom header are ignored and the peer address is the client IP. A client
  that connects directly cannot spoof its IP.
* **Trusted peer (default mode).** When the peer is trusted, `X-Forwarded-For`
  is walked right-to-left, skipping trusted hops, and the first untrusted
  address wins; `X-Real-IP` is used when there is no usable XFF. A value the
  client prepends on the left of XFF is therefore never used.
* **Legacy compatibility** (`security.trust_forwarded_ip_for_api_key_acl`,
  default `false`, also editable in the admin security settings). When enabled
  *and* the peer is trusted, the historical precedence is used: custom headers
  from `security.forwarded_client_ip_headers`, then `CF-Connecting-IP`,
  `X-Real-IP`, then the leftmost public `X-Forwarded-For` value. Requests from
  untrusted peers never use forwarded headers, even with the switch on. Only
  enable it when the edge overwrites (not appends) those headers.

Configure with YAML or the comma-separated environment variable
`SERVER_TRUSTED_PROXIES` (an empty value overrides YAML and trusts nothing).
Startup logs a warning when the list is empty or when the legacy switch is on.

| Deployment | `server.trusted_proxies` |
|------------|--------------------------|
| Nginx/Caddy on the same host, binary install | `127.0.0.1/32`, `::1/128` |
| Nginx on the host, Sub2API in Docker (bridge) | docker bridge gateway, e.g. `172.17.0.1/32` (`docker network inspect <project>_sub2api-network`) |
| Nginx/Caddy service in the same compose network | the compose network subnet, e.g. `172.18.0.0/16` |
| Cloudflare / CDN directly to origin | the CDN's published egress ranges; firewall the origin to them |
| CDN -> Nginx -> Sub2API | both the Nginx address and the CDN ranges |

Nginx must forward the chain:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP       $remote_addr;
```

**Upgrade note (one-time reset of the legacy switch).** Older releases
re-enabled the legacy switch automatically when `server.trusted_proxies` was
not configured, and the admin settings page wrote the effective value back to
the database on every save, so most existing installations have
`api_key_acl_trust_forwarded_ip=true` stored without anyone choosing it. On
the first start of this release a one-time migration (settings marker
`forwarded_client_ip_trust_reset_v3_migrated`) resets that stored value to
`false`, unless the config file or the environment variable
`SECURITY_TRUST_FORWARDED_IP_FOR_API_KEY_ACL` explicitly sets it to `true`.
The migration runs once; if an admin turns the switch back on in the settings
page afterwards, later restarts and upgrades keep it. Saving the settings page
no longer writes `true` back unless the admin actually switched it on.

Once a value is stored in the database it wins over the config file and the
environment. If you upgraded while `SECURITY_TRUST_FORWARDED_IP_FOR_API_KEY_ACL=true`
was set explicitly, the migration kept the stored `true` and wrote its marker;
removing the variable later does **not** turn the switch off (the startup log
keeps printing the legacy-precedence warning). Turn it off in the admin settings
page, or run
`UPDATE settings SET value='false' WHERE key='api_key_acl_trust_forwarded_ip';`
and restart every instance (the running process keeps its in-memory value until
restart or a settings save). Do not delete the marker to re-run the migration.

Fresh installs write only the migration markers (and the forwarded-header
list), not a value row for this switch, so the effective value follows the
config file / environment (default `false`) until an admin saves a change in
the settings page.

Deployments behind a proxy must set `server.trusted_proxies`, otherwise every
request appears to come from the proxy address (shared rate-limit buckets,
login lockout per proxy IP, IP allowlists matching the proxy).

Example for a proxy on the same host:

```yaml
server:
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
```

## Login lockout

Password logins (`POST /api/v1/auth/login` and the password check of the
pending OAuth account-adoption flow) share one failure counter per
**account + client IP** pair. The account is the normalized (trimmed,
lower-cased) email, the client IP is the value `ip.ClientIP` resolves (see
"Trusted client IPs" above) normalized by `ip.RateLimitKey` (IPv4 unchanged,
IPv4-mapped IPv6 `::ffff:a.b.c.d` counted as the IPv4 address, IPv6 zone
dropped and **grouped by /64**), and the pair is SHA-256 hashed into the Redis key
(`login_lockout:v2:{hash}:fail|lock`; the older account-only keys are no longer
read or written and expire on their own):

```yaml
security:
  login_lockout:
    enabled: true        # SECURITY_LOGIN_LOCKOUT_ENABLED
    max_failures: 10     # SECURITY_LOGIN_LOCKOUT_MAX_FAILURES
    window_seconds: 900  # SECURITY_LOGIN_LOCKOUT_WINDOW_SECONDS
    lockout_seconds: 900 # SECURITY_LOGIN_LOCKOUT_LOCKOUT_SECONDS
```

After `max_failures` failures within `window_seconds` from the same client IP,
that account + IP pair is locked for `lockout_seconds`; during the lock even the
correct password is rejected with HTTP 429 and `reason: LOGIN_LOCKED`. Every
attempt first reserves a slot atomically in Redis and only then runs the
password check, so concurrent requests can never run more than `max_failures`
password checks per window; requests beyond the threshold are rejected without
running bcrypt. Unknown emails are counted and locked the same way, so the
response never reveals whether an account exists. A successful login clears the
failure counter for that account + IP. State lives in Redis.

When Redis cannot be reached, password login still fails closed, but the
client sees **HTTP 429** (`{"error":"rate limit exceeded","message":"Too many
requests, please try again later"}`, with `Retry-After`), not 503: the per-IP
rate limiter on `POST /api/v1/auth/login` (and on
`/api/v1/auth/oauth/pending/bind-login`) runs first in fail-close mode and
rejects the request before the lockout code is reached. The lockout's own
503 (`SERVICE_UNAVAILABLE`) branch only applies to callers that bypass that
route-level limiter. For monitoring, a burst of 429 responses on the login
routes together with `[RateLimit] redis error ... mode=fail-close` in the logs
means Redis is down, not that users are being rate limited; logins recover as
soon as Redis is reachable again. Body difference: the lockout's own 429
carries `reason: LOGIN_LOCKED`, the Redis-down 429 does not. Known trade-off: an attacker who knows a user's email can only lock that user
out from the attacker's own IP, not from the user's IP; the flip side is that
an attacker who rotates source IPs gets a fresh per-account budget on every IP,
so per-account lockout alone does not stop distributed guessing. The per-IP
rate limits (built-in auth rate limit and the edge limits below) are the
backstop and must stay enabled.

**IPv6 /64 grouping.** Every IP-keyed counter uses `ip.RateLimitKey`: the
lockout's IP dimension, the built-in per-IP rate limits on all auth/OAuth/MCP/
payment-lookup routes, the panel public-IP rate limit, the in-process
invalid-credential abuse limiter (`api_key_auth_cache.invalid_abuse`) and the ops WebSocket
per-IP connection cap. IPv6 clients are counted per /64, because ISPs and
clouds usually hand a whole /64 to one subscriber or VM, so rotating addresses
inside it no longer resets the budget. Several users behind the same /64 share
one counter. Audit logs, access logs, session binding and API-key IP
allow/deny lists still see the full address returned by `ip.ClientIP`.

## Nginx baseline

Define shared zones in the `http` block. Tune rates to measured legitimate
traffic; the values below are conservative starting points, not universal
capacity targets.

```nginx
limit_conn_zone $binary_remote_addr zone=sub2api_conn:20m;
limit_req_zone  $binary_remote_addr zone=sub2api_auth:20m rate=5r/s;
limit_req_zone  $binary_remote_addr zone=sub2api_api:40m rate=30r/s;
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    client_header_timeout 10s;
    client_max_body_size 256m;
    large_client_header_buffers 4 16k;
    limit_conn sub2api_conn 40;

    location ~ ^/(auth|api/auth)/ {
        limit_req zone=sub2api_auth burst=10 nodelay;
        proxy_pass http://127.0.0.1:8080;
    }

    location ~ ^/(v1/)?(embeddings|alpha/search)$ {
        client_max_body_size 32m;
        limit_req zone=sub2api_api burst=60 nodelay;
        proxy_pass http://127.0.0.1:8080;
    }

    location / {
        limit_req zone=sub2api_api burst=60 nodelay;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 1800s;
        proxy_send_timeout 1800s;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

If Nginx gzip is enabled in the `http` block, keep `text/event-stream` out of
`gzip_types` and do not use `gzip_types *` for Sub2API. The
`proxy_buffering off` setting above prevents proxy buffering, but it does not
disable the gzip response filter. Use an explicit list for ordinary responses:

```nginx
gzip on;
gzip_types text/plain text/css application/json application/javascript application/xml image/svg+xml;
```

If a shared global configuration cannot exclude SSE by content type, set
`gzip off;` in the locations serving streaming API routes. This leaves gzip
available for the web UI and static assets.

Do not use an incoming `$http_x_forwarded_for` value unless Nginx real-IP
processing is restricted to explicit trusted proxy CIDRs.

## Caddy and CDN

The bundled `deploy/Caddyfile` sets a 64 KiB header limit, a 10-second header
timeout, a 256 MiB absolute body limit, and overwrites forwarded addresses from
the TCP peer. It is therefore a direct-to-Caddy baseline. Do not use its
`{remote_host}` forwarding lines unchanged behind a CDN: all clients would be
attributed to a CDN egress address, collapsing rejection aggregation and the
invalid-auth limiter onto unrelated users.

The bundled Caddy configuration leaves `flush_interval` unset so Caddy can
automatically flush `text/event-stream` responses while still propagating
client cancellation upstream. Do not set it globally: positive values can add
streaming latency, while Caddy 2.6.2's special `-1` mode also causes
reverse-proxied requests to continue after clients disconnect. The
configuration uses an explicit response content-type list for compression. Do
not replace that list with `text/*` or the shorthand `encode gzip zstd`: both
match `text/event-stream` and can buffer SSE until the response ends. Keep
streaming responses uncompressed while retaining compression for the web UI,
JSON, and static assets.

For a CDN deployment, first firewall the origin so only current CDN egress
CIDRs can connect. Then configure those exact ranges as Caddy trusted proxies
and derive upstream headers from Caddy's parsed `{client_ip}`. For example:

```caddyfile
{
	servers {
		trusted_proxies static 192.0.2.0/24 2001:db8:1234::/48
		trusted_proxies_strict
		client_ip_headers CF-Connecting-IP X-Forwarded-For
	}
}

api.example.com {
	reverse_proxy 127.0.0.1:8080 {
		header_up X-Real-IP {client_ip}
		header_up X-Forwarded-For {client_ip}
	}
}
```

Replace the documentation ranges with the CDN's published, automatically
maintained egress ranges. `CF-Connecting-IP` is safe here only because direct
origin access is blocked and Caddy trusts only those TCP peers. Configure
Sub2API `server.trusted_proxies` with the Caddy address/private subnet so the
application accepts only Caddy's rewritten headers.

Caddy core does not provide a general request-rate limiter; use a trusted
CDN/WAF, a supported rate-limit module, or host firewall controls.

At a CDN/WAF, configure connection limits, header/body limits, bot challenges,
and per-IP/ASN rates before traffic reaches the origin. Allow origin ingress
only from CDN egress CIDRs or a private load balancer. Keep the application port
off the public Internet.

## DDoS boundary

Application checks reduce amplification after a connection reaches Go. They
cannot absorb volumetric attacks, TLS floods, bandwidth saturation, or a large
distributed source set. Those require upstream network capacity, CDN/WAF
filtering, provider firewall rules, and origin isolation. Avoid high-cardinality
metrics or per-request database security logs during rejection storms.

## Setup wizard token / 安装向导 token

While the instance is not installed, the setup wizard prints a one-time token at startup:

```
[setup] Setup token: 0123456789abcdef0123456789abcdef
```

- `POST /setup/test-db`, `/setup/test-redis` and `/setup/install` require header `X-Setup-Token: <token>` (whitespace trimmed, constant-time compare).
- Missing → 401 `SETUP_TOKEN_REQUIRED`; wrong → 403 `SETUP_TOKEN_INVALID`; 10 wrong attempts per direct client IP within 15 minutes → 429 `SETUP_TOKEN_RATE_LIMITED` with `Retry-After`.
- The rate-limit key is the TCP peer address; `X-Forwarded-For` is ignored for this check.
- `GET /setup/status` stays public and returns `setup_token_required: true`.
- The token is regenerated on each restart and is not persisted. `AUTO_SETUP` (Docker env-based install) does not use the HTTP wizard and is unaffected.
