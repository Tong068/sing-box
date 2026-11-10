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
  "tag": "tongls-out",
  "server": "proxy.example.com",
  "server_port": 443,
  "password": "REPLACE_WITH_GENERATED_PASSWORD",
  "path": "/",
  "handshake_timeout": "10s",
  "header_padding_min": 128,
  "header_padding_max": 512,
  "idle_session_check_interval": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 0,
  "client_metadata": "",
  "tls": {
    "enabled": true,
    "server_name": "proxy.example.com"
  }
}
```

The example password is a placeholder. Generate a distinct strong password with
`sing-box generate rand --base64 32` and configure it at both endpoints.

### Fields

#### server / server_port

==Required==

Tongls server address and port.

#### password

==Required==

Password matching a server user. It authenticates the channel-bound HTTPS upgrade
and the inner session. The outer HTTP header contains a proof, not the password.

#### path

Upgrade path, default `/`; it must match the server. Use an absolute escaped path
of at most 2,048 bytes without a query or fragment. It is not an authentication secret.

#### handshake_timeout

Deadline covering TCP/TLS establishment and HTTP upgrade. Default `10s`; zero uses
the default, and negative values are rejected. Every new session adds one HTTP
upgrade request/response. Existing session reuse amortizes this cost.

#### header_padding_min / header_padding_max

Inclusive byte-length range for the outer HTTP `Padding` header value. Both zero
use the default 128–512; otherwise `0 <= min <= max <= 4096`. Characters use
cryptographic randomness and a URL-safe ASCII alphabet. This length excludes the
field name and HTTP framing and does not specify TLS/TCP packet boundaries.
This mechanism is independent of inner padding and adds no intentional delay.

#### initial_padding_scheme

Optional line array used before the first authenticated server settings exchange.
The default profile changes upstream `0=30-30` to `0=16-256`, producing 50–289
bytes of authentication plaintext instead of a fixed 64. These are application
lengths, not network packet sizes. The server may replace the profile using the
existing settings exchange; use a matching server `padding_scheme` to retain the
policy in later sessions. Explicit profiles are copied per client.

Validation limits text to 16 KiB, `stop` to 0–1024 and each record to 64 range/check
entries. Authentication record `0` must have one positive range fitting uint16;
other ranges must be positive and ordered, with a total maximum size of at most
1 MiB per record. Duplicate/unknown keys and records outside `stop` are rejected.
`stop=0` alone disables the initial inner padding policy.

#### idle_session_check_interval / idle_session_timeout / min_idle_session

Inherited session-pool controls: check idle sessions every `30s` by default, expire
sessions idle for `30s` by default, and retain at least `min_idle_session` idle
sessions (default zero). They do not disable the authenticated HTTPS entry.

#### client_metadata

Optional metadata sent inside the authenticated AnyTLS session. Empty by default;
see [AnyTLS client metadata](/manual/misc/anytls-client-metadata/) for context.

#### tls

==Required==

See [outbound TLS](/configuration/shared/tls/#outbound). Tongls requires standard
Go TLS 1.3 with certificate-chain and hostname verification. Private CAs may be
supplied using `certificate` or `certificate_path`. It rejects `insecure`,
`disable_sni`, pin-only verification, uTLS, REALITY, kTLS, fragmentation and spoofing.
ALPN is `http/1.1`; an explicit list must contain only that single value.

### Dial fields

See [dial fields](/configuration/shared/dial/). TCP fast open is unsupported.
