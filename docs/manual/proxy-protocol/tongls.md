---
icon: material/tunnel
---

# Tongls

Tongls is an independent protocol derived from AnyTLS, configured with `type: "tongls"`.
It adds a real HTTPS entry and TLS-session-bound authentication before the existing
AnyTLS login, frames and session reuse. The original `anytls` implementation and
configuration remain separate. Selecting `tongls` always enables the authenticated
HTTPS entry; no extra switch is required. This local protocol is not an upstream
AnyTLS feature or a claim of invisibility.

```text
TCP → verified TLS 1.3 → authenticated HTTP/1.1 Upgrade → AnyTLS session → streams
                         ordinary HTTP/1.1 or HTTP/2 → fixed website backend
```

The Tongls listener does not inspect an unauthenticated byte prefix as an
AnyTLS login. Native Go HTTP parsing handles requests, and requests that do not
qualify for an authenticated upgrade use the real website reverse proxy.
The configured website must be deployed separately.

## Compatibility and boundaries

- Both endpoints must use a Tongls-capable build and `type: "tongls"`.
  Tongls is incompatible with ordinary AnyTLS endpoints and the previous local
  `anytls.private` prototype. There is no automatic downgrade.
- Existing `type: "anytls"` configurations continue to use the original implementation
  and need no migration. Tongls's inner core fork is tested against the pinned upstream
  AnyTLS library in both directions, but its outer handshake is a separate protocol.
- The inner AnyTLS protocol, stream handling, session reuse and existing
  UDP-over-TCP adaptation are retained. The physical transport remains TCP.
- Tongls requires its own HTTPS listener; inbound detours and injected
  connections are unsupported. TLS must terminate at the Tongls listener:
  a TLS-terminating CDN or reverse proxy in front would change the exporter
  and invalidate authentication. An opaque TCP relay does not terminate TLS.
- Standard Go TLS 1.3 and certificate-chain/hostname verification are mandatory.
  Private CAs are supported. uTLS, REALITY, kTLS, `insecure`, `disable_sni`,
  pin-only verification, TLS fragmentation and spoofing are not supported in
  Tongls. The server does not request TLS client certificates.

The server serves real `h2` and `http/1.1`. The Tongls client negotiates
`http/1.1`, because HTTP/1.1 Upgrade is the tunnel mechanism; normal HTTP/2
requests still use the website. This does not reproduce a browser TLS stack.
Go TLS behavior, HTTP/1.1 use, sizes, timing, destinations and connection reuse
remain observable. Changing a fixed length or serving a website alone does not
prove that a classifier or active prober can no longer identify the service.

Tongls currently requires the modified sing-box at both endpoints. A stock Mihomo client does not implement Tongls; support there would require a separate implementation.

## Deployment

Use a domain and valid certificate under your control, and a fixed plaintext
HTTP website backend. The examples use `127.0.0.1:8080`; do not use an HTTPS port
there. Configure the website's own request-body and resource limits.

Generate a distinct strong password for each user:

```shell
sing-box generate rand --base64 32
```

Replace `REPLACE_WITH_GENERATED_PASSWORD` in both configurations, the domain and
certificate paths. The HTTP proof is not a second independent factor, and a
weak password remains weak. Do not log passwords, TLS exporters or proofs.

### Server

```json
{
  "inbounds": [
    {
      "type": "tongls",
      "tag": "tongls-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "name": "tongls-client",
          "password": "REPLACE_WITH_GENERATED_PASSWORD"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "/path/to/fullchain.pem",
        "key_path": "/path/to/private-key.pem"
      },
      "path": "/",
      "fallback": {
        "server": "127.0.0.1",
        "server_port": 8080
      },
      "handshake_timeout": "10s",
      "idle_timeout": "5m",
      "max_connections": 1024
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
```

### Client

```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "local",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "tongls",
      "tag": "tongls-out",
      "server": "proxy.example.com",
      "server_port": 443,
      "password": "REPLACE_WITH_GENERATED_PASSWORD",
      "tls": {
        "enabled": true,
        "server_name": "proxy.example.com"
      },
      "path": "/",
      "handshake_timeout": "10s",
      "header_padding_min": 128,
      "header_padding_max": 512
    }
  ],
  "route": {
    "final": "tongls-out"
  }
}
```

Configure proxy-domain DNS resolution as for an ordinary AnyTLS deployment.
Existing idle-session options can still be used; they are not reset for each
stream. Field reference: [inbound](/configuration/inbound/tongls/) and
[outbound](/configuration/outbound/tongls/).

The fallback is always the administrator-selected HTTP backend. It does not
use incoming target addresses, normal proxy routing rules or environment HTTP
proxy settings. The private `Proxy-Authorization: Tongls ...` field is stripped
by normal reverse-proxy hop-by-hop processing; website `Authorization` remains
available without special rewriting. Malformed HTTP receives native HTTP parsing behavior, rather than
an AnyTLS authentication diagnostic.

## Tongls handshake v1

After verified TLS 1.3 establishment, the client sends a bodyless HTTP/1.1
`GET` to the configured path with:

- `Connection: Upgrade`
- `Upgrade: tongls-v1`
- `Proxy-Authorization: Tongls <canonical-standard-base64-token>`
- A randomized `Padding` header value

The path is routing configuration, not a secret. It must be an absolute escaped
path of at most 2,048 bytes without a query or fragment. Both endpoints use the
same path. HTTP/2 and requests with bodies are not upgrade candidates.

The token contains a 16-byte credential selector followed by a 32-byte request
proof, encoded as 64 canonical standard Base64 characters. Its exact inputs are:

```text
K = SHA256(password bytes)
selector = first16(HMAC-SHA256(K, "Tongls-v1 credential selector"))
E = TLS-Exporter("EXPORTER-Tongls-v1", empty context, 32 bytes)
M = "Tongls-v1 request\x00" || E
    || len32be(method) || method || len32be(host) || host || len32be(uri) || uri
proof = HMAC-SHA256(K, M)
token = Base64(selector || proof)
```

`host` is the HTTP Host value, including the port when present. `uri` is the
exact request URI. Field lengths count bytes. The server selects a credential
by its selector and verifies the complete request proof with HMAC comparison.
Unknown selectors perform one HMAC with a random dummy key. Verification does
not run one HMAC per configured user, bounding that computation independently
of user count. This does not promise constant-time map lookup or identical
network timing for all requests.
A proof copied to another TLS connection does not validate, even with the same
host and path. This claim is limited to cross-connection proof reuse; it does
not hide traffic patterns or protect a disclosed password.

On success the server sends an HTTP/1.1 `101 Switching Protocols` response with
the matching Connection/Upgrade headers. Buffered bytes are retained on both
sides. The original AnyTLS password-hash authentication and padding prologue
then occur, followed by the existing settings, streams and session lifecycle.
An HTTP proof does not replace or redefine the AnyTLS data-frame protocol.
Only after successful HTTP authentication does the server collect the inner
34-byte authentication header and its declared padding under a fresh deadline.
This accepts fragmented inner authentication without imposing an AnyTLS
32-byte wait on an ordinary short HTTP request.

On unsuccessful or absent authentication the request follows the website path;
no private authentication error or challenge is returned. Invalid, missing or
duplicate proof headers never enter the AnyTLS parser. The HTTP server and
website may still return ordinary HTTP errors.

## Padding and cost

Two independent controls are used:

| Control | Default and meaning |
| --- | --- |
| Outer HTTP header padding | 128–512 ASCII bytes inclusive in the `Padding` value, excluding the header name and framing. Cryptographically random length and characters; configurable up to 4,096 bytes. |
| Initial inner AnyTLS profile | The upstream default profile with only `0=30-30` changed to `0=16-256`. The inherited upper-exclusive sampler yields 16–255 padding bytes, hence 50–289 authentication plaintext bytes. |

When both outer padding bounds are zero, defaults are used. Otherwise they must
satisfy `0 <= min <= max <= 4096`. No artificial scheduling delay is added.
The `initial_padding_scheme` outbound field selects a per-client initial profile
before the first settings exchange. Authenticated server updates still replace
it; a matching server `padding_scheme` maintains the policy across later sessions.

These lengths describe plaintext writes/header values, not TCP packets or TLS
records. The Tongls default removes the fixed 64-byte inner-authentication
condition, but introduces an HTTP request/response of its own. A new session
therefore has an extra HTTP upgrade round trip and additional bytes; reusing
the AnyTLS session amortizes this cost. Measure cold and reused sessions
separately and do not disable reuse only on the comparison protocol.

## Resource limits and verification

The Tongls server defaults to a 10-second initial TLS/HTTP-header deadline,
a 5-minute connection idle timeout and 1,024 concurrent connections. The limit
includes unverified connections, website connections and hijacked AnyTLS
sessions; it is not a per-session stream limit. Activity on the encrypted socket
refreshes the idle deadline. Server shutdown also closes hijacked sessions.
After a successful HTTP upgrade, reading the inner AnyTLS authentication
prologue has a separate `handshake_timeout` deadline, also 10 seconds by default.

The HTTP server configures `MaxHeaderBytes` to 8,192, with Go's normal parser
buffering allowance. The client limits upgrade-response header parsing to
16 KiB. These values are not total memory-usage guarantees. The fixed backend
has a 10-second dial and response-header timeout and a separately bounded idle
connection pool; the website still needs its own application limits.

Run only the relevant packages when packet-driver tests are unavailable:

```shell
go test ./transport/tongls ./transport/tonglshttp ./protocol/tongls -count=1 -timeout=90s
go vet ./transport/tongls ./transport/tonglshttp ./protocol/tongls
go test ./transport/tongls -run '^$' -fuzz '^FuzzInitialPaddingScheme$' -fuzztime=10s
go test ./transport/tonglshttp -run '^$' -fuzz '^FuzzAuthorization$' -fuzztime=10s
go test ./transport/tonglshttp -run '^$' -fuzz '^FuzzPath$' -fuzztime=10s
go test ./protocol/tongls -run '^$' -bench '^BenchmarkTonglsCost$' -benchtime=100x -count=3 -timeout=90s
```

The tests cover upstream/local inner-protocol interoperability, retained session
reuse, valid Tongls upgrades, ordinary HTTP/1.1 and HTTP/2 website requests,
wrong/replayed/tampered proofs, buffered-byte preservation, certificate checking,
deadline/cancellation/connection limits and shutdown. The website comparisons
use the same fixed backend and compare selected responses against an ordinary
reverse proxy; they do not measure a censor's detection rate.

`BenchmarkTonglsCost` compares original AnyTLS and Tongls with a 16 KiB request
and response on the local loopback interface. Both cold cases reset their session
pools after every sample; both warm cases retain reuse after an unmeasured priming
stream. It reports aggregate time, allocation, TLS handshakes per operation and
first-byte latency percentiles. The target is an in-process echo router, not a
remote application. Windows clocks may not resolve very short warm samples;
`unresolved-ttfb-fraction` reports that fraction, and zero percentiles are omitted
rather than interpreted as zero latency. This benchmark measures implementation
cost, not resistance to traffic classification.

For a before/after experiment, keep the website, certificate, TLS implementation,
workload and network path fixed. Test GET/HEAD, unknown paths, wrong complete
proofs, short/slow input, invalid HTTP, early close and ALPN variations. Record
response bytes, closure behavior and timing, plus resource use. Compare cold and
reused sessions separately. Use captures for actual TLS record and packet sizes,
and report traffic overhead and p95 latency alongside detection results.

Confirmed implementation properties should be stated narrowly: the
unauthenticated entry uses real HTTP behavior; defined website-response test
cases match their baseline; cross-TLS proof reuse is rejected; and the fixed
64-byte default inner-authentication write is removed in Tongls.
No public-network capture study, controlled-loss result or censorship-classifier
improvement is implied by those properties. A lower detection rate requires
measurement at a fixed false-positive rate on representative held-out traffic.

### Local validation: November 10, 2026

The table records validation of the pre-rename AnyTLS private prototype. Renamed targeted tests check the same behaviors; historical fuzz counts do not imply that those runs were repeated after renaming.

Targeted tests, configuration round trips, JSON Schema, `go vet`, and the CLI build passed on Windows amd64 with Go 1.25.5.
Only selected packages were tested; this run does not invoke WinDivert. Race detection, public-network packet capture, and classifier detection rates have not been evaluated.

| Check | Observed result |
| --- | --- |
| Ordinary GET with the same certificate | Ordinary AnyTLS closes without an HTTP response; Tongls returns HTTP 200 from the test website. Neither routes an unauthenticated proxy request. |
| Short HTTP, malformed HTTP, and an invalid proof | The specified test responses match an ordinary reverse proxy to the same backend after normalizing Date. This does not establish timing equivalence for all requests. |
| Copying a proof to another TLS connection or changing Host/path | No tunnel is opened; the request follows the ordinary HTTP path. |
| Different outer and inner authenticated users | Proxy routing is rejected. |
| Four sequential proxy streams | Only one TLS connection is established; session reuse is retained. |
| Fragmented authentication, deadlines, and shutdown | Valid fragments work, timeouts release connections, and shutdown closes hijacked sessions. |

Three ten-second fuzz runs processed 1,953,486 initial-padding inputs, 344,141 authorization inputs, and 314,644 path inputs without failures.
These observations verify the specified behaviors, not success rates against unknown detection systems.

## Migrating the previous private prototype

Ordinary AnyTLS users do not need to change configuration. To migrate the earlier local prototype only:

1. Change `"type": "anytls"` to `"type": "tongls"` at both ends.
2. Move `path`, `fallback`, timeouts, connection limits and header-padding fields out of the former `private` object into the corresponding inbound/outbound object.
3. Delete the `private` object and its `enabled` switch; retain `tls.enabled`.
4. Upgrade both endpoints together. Tongls has renamed the HTTP upgrade token, authentication scheme and TLS exporter domains, so the old prototype cannot interoperate.

The client and server examples on this page already use the flat configuration. Original `anytls` does not accept these Tongls extension fields.
