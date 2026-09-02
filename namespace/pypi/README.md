# Innsegl

**Innsegl** (Norwegian, from Old Norse *innsigli*: a seal pressed on a document
to prove who issued it) is an open-source system for non-repudiable AI agent
identity and attribution — single-purpose SPIFFE/SPIRE identities per agent
run, Sigstore-signed commits carrying agent identity trailers, an append-only
Merkle-anchored ledger, and a public verification surface that a third party
can re-derive without trusting the operator.

## This package is a name reservation

Innsegl is written in Go. This package exists so that the name `innsegl`
belongs to the project, and it is not empty: installing it prints where the
real implementation lives.

| | |
|---|---|
| Source | <https://github.com/Raymalian/innsegl> |
| Home | <https://innsegl.dev> |
| Go module | `innsegl.dev/innsegl` |
| npm | `innsegl`, and the `@innsegl` scope |
| PyPI | `innsegl` |
| Licence | Apache-2.0 |

## Why the name is defended rather than administered

Innsegl's entire product is that you can check who produced an artifact without
trusting whoever handed it to you. A package published under Innsegl's own name
by someone else is that claim inverted — and a developer reaching for an
attribution tool is precisely the developer least likely to expect one. The
project's threat model records the namespace as asset **A6** and typosquatting
as abuse case **AB-09**.

**A package claiming to be Innsegl that is not linked from the repository above
is not ours.** Report it: <https://github.com/Raymalian/innsegl/security>
