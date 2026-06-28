# ADR 0001: TLS Uprobe Support

## Status

Accepted for Phase 5 implementation.

## Context

Prism must provide encrypted-traffic visibility without exporting TLS keys,
authorization material, cookies, request bodies, or arbitrary decrypted payload.
The Phase 5 scope allows approved TLS library integrations and requires
connection-level telemetry fallback for unsupported libraries.

## Decision

Prism will keep TLS request metadata tracing disabled by default. When enabled,
the agent evaluates an explicit TLS library allowlist before selecting any
uprobe integration.

OpenSSL is the only supported uprobe target in Phase 5. BoringSSL and rustls are
recognized library identities, but they fall back to connection-level telemetry
until their call surfaces and safety constraints are validated.

The TLS metadata policy permits only low-cardinality semantic metadata:

- method
- status
- protocol
- W3C trace context

The policy rejects TLS keys, secrets, cookies, authorization headers, proxy
authorization headers, set-cookie headers, and bodies.

## Consequences

Encrypted flows always produce connection-level telemetry from P5-01. Approved
OpenSSL deployments can opt into metadata uprobes, while unsupported or
non-allowlisted libraries remain observable at the connection level. This keeps
the default posture privacy-preserving and avoids pretending that full request
metadata is available for every encrypted workload.
