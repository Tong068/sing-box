---
icon: material/tunnel
---

Tongls is a separate local protocol derived from AnyTLS. Its type is `tongls`;
the original `anytls` implementation and configuration remain available unchanged.
Tongls always uses an authenticated HTTPS upgrade. Both endpoints must support
Tongls; neither ordinary AnyTLS nor the earlier private-mode prototype is compatible.
See the [protocol and deployment guide](/manual/proxy-protocol/tongls/).

### Structure

```json
{
  "type": "tongls",
  "tag": "tongls-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "client",
      "password": "REPLACE_WITH_GENERATED_PASSWORD"
    }
  ],
  "path": "/",
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "handshake_timeout": "10s",
  "idle_timeout": "5m",
  "max_connections": 1024,
  "tls": {
    "enabled": true,
    "certificate_path": "/path/to/fullchain.pem",
    "key_path": "/path/to/private-key.pem"
  }
}
```

The example password is a placeholder. Generate a distinct strong password with
`sing-box generate rand --base64 32` and configure it at both endpoints.

### Fields

#### users

==Required==

Between 1 and 1,024 users, each with a unique nonempty `name` and a unique nonempty
`password`. Outer HTTPS authentication and inner AnyTLS authentication must identify
the same user. A weak password is not strengthened by the extra handshake.

#### path

The upgrade path, default `/`, must match the client. Use an absolute escaped path
of at most 2,048 bytes without a query or fragment. This value is not a secret.

#### fallback

==Required==

A fixed plaintext HTTP website backend, expressed as `server` and nonzero
`server_port`. TLS terminates at Tongls; do not use an HTTPS backend port.
Prefer a local backend with its own request/body/resource limits.

Ordinary HTTP/1.1 and HTTP/2 requests, including unsuccessful upgrade authentication,
use this fixed reverse proxy. Unauthenticated requests cannot select proxy targets.
Backend dialing ignores environment HTTP proxies and ordinary proxy routing rules.
Normal reverse-proxy processing strips `Proxy-Authorization: Tongls ...`; the
website's `Authorization` remains available. Malformed HTTP uses the native parser.

#### handshake_timeout

Initial TLS/HTTP-header deadline and HTTP header-read timeout; also a separate
post-upgrade deadline for collecting the inner authentication prologue. Each phase
defaults to `10s`. Zero uses the default; negative durations are rejected.

#### idle_timeout

Connection idle timeout, default `5m`, refreshed by activity on the encrypted socket.
Zero uses the default; negative durations are rejected.

#### max_connections

Accepted-connection limit including TLS handshakes, website connections and
upgraded sessions. Default `1024`, range 1–65,536; zero uses the default.
This does not limit streams within a session. The HTTP server configures
`MaxHeaderBytes` to 8,192 with the normal Go parser buffering allowance.

#### padding_scheme

Optional line array configuring the inherited AnyTLS padding policy. Tongls's
default is the upstream profile with `0=16-256` instead of `0=30-30`. The inherited
upper-exclusive sampler yields 50–289 bytes of inner authentication plaintext;
these are not TLS record or TCP packet lengths. The authenticated settings exchange
can update the client's later-session policy.

Explicit profiles use the same strict limits as outbound
[`initial_padding_scheme`](/configuration/outbound/tongls/#initial_padding_scheme).

#### tls

==Required==

See [inbound TLS](/configuration/shared/tls/#inbound) for certificate options.
Tongls requires standard certificate TLS 1.3 and serves real `h2` and `http/1.1`.
If `alpn` is supplied, only those names are accepted; the listener enables both.
`insecure`, REALITY, kTLS and TLS client-certificate authentication are unsupported.

### Listen fields

See [listen fields](/configuration/shared/listen/). Tongls requires its own HTTPS
listener and does not support inbound `detour` or injected connections. The physical
transport is TCP; inner AnyTLS session reuse and UDP-over-TCP remain available.
