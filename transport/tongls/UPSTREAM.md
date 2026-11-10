# Tongls stream core: managed sing-anytls fork

This directory contains the production Go source and license from:

- Module: `github.com/sagernet/sing-anytls`
- Pinned version: `v0.0.0-20260928104022-580984e4d8cb`
- Revision: `580984e4d8cb`
- Original copyright and license: retained verbatim in `LICENSE` (GPL-3.0-or-later).

The module cache is not modified. Original AnyTLS continues to use the unchanged
external module in production. This independently named `transport/tongls`
package is used only by Tongls; the original module also provides an independent
interoperability-test reference. Keep future upstream updates scoped and review
the local changes below when rebasing.

## Local changes

1. `ClientOptions.InitialPaddingScheme` selects and validates a per-client
   initial padding profile before the first authenticated settings exchange.
   An empty value keeps the upstream default. The selected bytes are copied,
   and the existing server-delivered update mechanism is unchanged.
2. `TonglsPaddingScheme` changes only the upstream profile's `0=30-30` entry
   to `0=16-256`. With the inherited upper-exclusive sampler this produces
   50..289 bytes of authentication plaintext instead of a fixed 64 bytes.
   It does not claim reduced detection probability or browser equivalence.
3. Explicit initial profiles use strict validation: at most 16 KiB of text,
   `stop` from 0 through 1024, at most 64 range/check entries per record,
   at most 1 MiB of maximum requested padding sizes per record, and one
   authentication-padding range representable by its uint16 wire length.
   Duplicate/unknown keys, reversed/invalid ranges and ignored records are
   rejected. `stop=0` without a record disables the initial padding policy.
4. Client authentication writes reject a generated padding size above 65535
   before allocating or truncating the uint16 length. This also protects
   subsequent connections after an oversized server-delivered profile.

5. The package, file name and diagnostic prefix use Tongls. Upstream attribution,
   copyright and license remain intact.

The inner AnyTLS commands, authentication layout, framing, session reuse, stream
semantics and original default profile are unchanged. The separate Tongls
HTTP/TLS entry mechanism is implemented in `transport/tonglshttp`; its outer
handshake is not compatible with ordinary AnyTLS or the earlier private prototype.

## Verification

`go test ./transport/tongls` includes upstream-client/local-server and
local-client/upstream-server exchanges, first-authentication length checks,
server profile-update checks and invalid-profile tests. No packet-driver or
Internet access is required by these tests.
