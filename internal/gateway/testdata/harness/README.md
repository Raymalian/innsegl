# Harness request-shape fixtures

Recorded request shapes -- path and headers only, never a body, never a real
credential, never a real session id (every id here is synthesised) -- for
each harness version the gateway's harness-shape guard recognises (GW-012,
`internal/gateway/harness.go`).

A new harness version adds a new directory here, `<harness>-<version>/`
(see `claude-code-2.1/`). It never edits an existing one: a fixture set is
pinned per version once merged, the same way a released schema version's
golden vectors are pinned.
