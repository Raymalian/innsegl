# SPDX-License-Identifier: Apache-2.0
#
# SPIRE server authorization policy — scope the MCP admin credential to the
# agent subtree (RM-015, #23; test catalog SPI-005; threat model AB-10).
#
# WHY THIS FILE EXISTS
# --------------------
# ADR-0011 recorded the gap it closes, verbatim:
#
#   "admin_ids grants *full* admin. It does not scope entry creation to the
#    /agent/ subtree, which is what SPI-005 and threat-model AB-10 require."
#
# MEASURED, not inferred: before this file existed, an X509-SVID bearing
# spiffe://innsegl.dev/innsegl/mcp called BatchCreateEntry over the admin API
# for spiffe://innsegl.dev/innsegl/rogue and SPIRE answered
# `status:{message:"OK"} entry:"a4f36af5-…"`. That is AB-10 — steal the admin
# credential (threat-model asset A2), mint identities anywhere in the trust
# domain — and it is what this policy refuses. The refusal has to come from
# SPIRE: a client-side check does not run inside a stolen credential.
#
# WHAT REPLACES WHAT
# ------------------
# SPIRE has one authorization policy, and a configured one REPLACES the built-in
# default wholesale (pkg/server/authpolicy). So this file is upstream's default
# policy for SPIRE 1.15.3, unchanged, plus one extra condition on the admin
# path. `data.apis` is upstream's own table, shipped verbatim beside this file
# as authz-policy-data.json, so every non-admin caller class — local socket,
# agent, downstream, anonymous — behaves exactly as it does with no policy
# configured. Only `allow_if_admin` is narrowed.
#
# Consequence of shipping upstream's table: a SPIRE upgrade that adds an RPC
# leaves that RPC absent from the table, and it is then denied to everyone
# rather than allowed to anyone. That is fail-closed and it is loud; the fix on
# a version bump is to re-copy authz-policy-data.json from the matching SPIRE
# tag and re-run TC-SPI.
#
# WHAT IS NOT SCOPED, STATED RATHER THAN IMPLIED
# ----------------------------------------------
#  * The LOCAL socket keeps full admin. It is unauthenticated by construction,
#    it is what `deploy/compose/spire/register.sh` uses to create the
#    infrastructure entries the stack needs before any MCP exists, and ADR-0011
#    contains it with a private tmpfs rather than with authorization. Narrowing
#    `allow_if_local` here would break bootstrap and would not contain a caller
#    that already has full admin on an unauthenticated socket.
#  * BatchDeleteEntry is NOT scoped, and cannot be: its request carries opaque
#    entry IDs, not SPIFFE IDs, and rego cannot resolve one to the other. A
#    stolen admin credential can therefore delete any entry in the trust
#    domain. That is denial of service and orphaning, not forged attribution —
#    AB-10 is about minting. Detection is entry reconciliation (RM-019, AB-11).
#    See ADR-0012.
#  * MintX509SVID and MintWITSVID are denied to admin outright rather than
#    scoped, and could not be scoped even if we wanted them: the SPIFFE ID
#    lives inside a DER-encoded CSR, which rego cannot parse.
#    MintJWTSVID IS allowed, and IS scoped — RM-023 (#31), ADR-0019. Its
#    request carries the SPIFFE ID in `input.req.id`, so the same subtree rule
#    that scopes an entry batch scopes it. Scoping it is not optional: minting
#    an SVID needs no registration entry, so an unscoped MintJWTSVID would
#    route straight around everything else this policy scopes and would be
#    AB-10 by another road. The LOCAL socket keeps all three: SPI-005's own
#    harness uses `spire-server x509 mint` on that socket to obtain the admin
#    caller SVID it then tests with.
#
# The trust domain below is a PROTECTED STRING (doc 01 §1, VERSIONING.md). It is
# spelled out rather than parameterised for the same reason server.conf spells
# it out, and with one extra property: a copy of this policy pointed at another
# trust domain denies every scoped method rather than quietly widening.

package spire

# The result object SPIRE queries (data.spire.result). Its five members are
# upstream's contract, not ours.
result = {
	"allow": allow,
	"allow_if_admin": allow_if_admin,
	"allow_if_local": allow_if_local,
	"allow_if_downstream": allow_if_downstream,
	"allow_if_agent": allow_if_agent,
}

default allow = false

default allow_if_admin = false

default allow_if_local = false

default allow_if_downstream = false

default allow_if_agent = false

# ---------------------------------------------------------------------------
# Unchanged from upstream: local, downstream, agent and anonymous callers are
# authorized exactly as the built-in default authorizes them.
# ---------------------------------------------------------------------------

allow_if_local = true if {
	r := data.apis[_]
	r.full_method == input.full_method
	r.allow_local
}

allow_if_downstream = true if {
	r := data.apis[_]
	r.full_method == input.full_method
	r.allow_downstream
}

allow_if_agent = true if {
	r := data.apis[_]
	r.full_method == input.full_method
	r.allow_agent
}

allow = true if {
	r := data.apis[_]
	r.full_method == input.full_method
	r.allow_any
}

# ---------------------------------------------------------------------------
# Narrowed: an admin SPIFFE ID is authorized only for the methods the MCP needs
# (IP §6.10, "entry create/delete only, scoped to the agent subtree"), and only
# when every SPIFFE ID the request names lies in that subtree.
#
# `r.allow_admin` is still required, so this policy can never authorize an admin
# caller for something upstream's default would refuse. It only subtracts.
# ---------------------------------------------------------------------------

allow_if_admin = true if {
	r := data.apis[_]
	r.full_method == input.full_method
	r.allow_admin

	mcp_admin_methods[input.full_method]
	admin_scope_ok
}

# The admin surface, in full. Everything else upstream marks `allow_admin` —
# CreateJoinToken, BanAgent, the bundle and federation APIs, the local-authority
# APIs, MintX509SVID, MintWITSVID — is denied to an admin SPIFFE ID by omission.
# IP §6.10 is the standard being met: "least-privilege (entry create/delete
# only, scoped to the agent subtree of the trust domain)".
#
# Each member is here because a tool in IP §4 or a component of E3 needs it:
#
#   register_agent            BatchCreateEntry; ListAgents for the parent node ID
#   get_credential            MintJWTSVID                     (RM-023, ADR-0019)
#   retire_agent              BatchDeleteEntry
#   reaper (RM-017),          ListEntries, GetEntry, CountEntries,
#   reconciler (RM-019)       BatchUpdateEntry
#
# Adding a member widens the blast radius of threat-model asset A2 and takes an
# ADR plus its own denial test. MintJWTSVID arrived with both: ADR-0019, and
# TestGetCredentialAgainstRealSPIRE in internal/mcp/get_credential_test.go,
# which mints in-subtree as a positive control and then asserts nine
# out-of-subtree shapes are refused.
mcp_admin_methods := {
	"/spire.api.server.entry.v1.Entry/BatchCreateEntry",
	"/spire.api.server.entry.v1.Entry/BatchUpdateEntry",
	"/spire.api.server.entry.v1.Entry/BatchDeleteEntry",
	"/spire.api.server.entry.v1.Entry/ListEntries",
	"/spire.api.server.entry.v1.Entry/GetEntry",
	"/spire.api.server.entry.v1.Entry/CountEntries",
	"/spire.api.server.agent.v1.Agent/ListAgents",
	"/spire.api.server.svid.v1.SVID/MintJWTSVID",
}

# Methods whose request body carries the SPIFFE IDs being created or moved.
# BatchUpdateEntry is here and not merely tolerated: without it, an admin could
# create an in-subtree entry and then move it anywhere.
entry_batch_methods := {
	"/spire.api.server.entry.v1.Entry/BatchCreateEntry",
	"/spire.api.server.entry.v1.Entry/BatchUpdateEntry",
}

# Methods whose request names ONE SPIFFE ID directly, in `input.req.id`.
# MintJWTSVID is the only one: MintX509SVID and MintWITSVID carry theirs inside
# a DER-encoded CSR and are denied by omission from mcp_admin_methods above.
mint_id_methods := {
	"/spire.api.server.svid.v1.SVID/MintJWTSVID",
}

default admin_scope_ok = false

# Read-only methods on the allowlist name no SPIFFE ID to scope. Both scoped
# sets are excluded here, so adding a method to either one cannot accidentally
# leave it matching this rule and therefore unscoped.
admin_scope_ok = true if {
	not entry_batch_methods[input.full_method]
	not mint_id_methods[input.full_method]
}

# Every entry in the batch, with no exception and no empty batch.
admin_scope_ok = true if {
	entry_batch_methods[input.full_method]
	count(input.req.entries) > 0
	every e in input.req.entries {
		agent_subtree(e.spiffe_id)
	}
}

# The one identity a mint names. Same subtree rule as an entry batch, and for
# the same reason: an SVID minted outside spiffe://innsegl.dev/agent/{a}/{b}/{c}
# is a forged attribution, and minting needs no registration entry, so this is
# the only place it can be refused. `input.req.id` absent — protobuf omitempty
# on a mint request with no id — leaves agent_subtree undefined, which denies.
admin_scope_ok = true if {
	mint_id_methods[input.full_method]
	agent_subtree(input.req.id)
}

# agent_subtree holds for exactly the SPIFFE ID scheme of doc 01 §1:
#
#   spiffe://innsegl.dev/agent/{agent-type}/{task-id}/{run-id}
#
# Structure only: four non-empty path segments under /agent. The character
# grammar (doc 02 §5) is enforced by the client and by the event schema, which
# is where a malformed-but-in-subtree ID is a validation failure rather than an
# authorization one. What this rule owns is containment — nothing outside the
# subtree, and no shorter or deeper path inside it.
#
# A missing trust_domain or path is absent from the JSON entirely (protobuf
# omitempty), so an undefined reference denies. Fail closed by construction.
agent_subtree(id) if {
	id.trust_domain == "innsegl.dev"
	parts := split(id.path, "/")
	count(parts) == 5
	parts[0] == ""
	parts[1] == "agent"
	parts[2] != ""
	parts[3] != ""
	parts[4] != ""
}
