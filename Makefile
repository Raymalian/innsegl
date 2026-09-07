# innsegl - build, test and lint entry points.
#
# Deliberately thin: CI runs exactly the targets a developer runs locally, so a
# green pull request and a green working copy mean the same thing.

BINARY      := innsegl
MODULE      := innsegl.dev/innsegl
CMD         := ./cmd/innsegl
VERSION_PKG := $(MODULE)/internal/version

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
# The commit date rather than wall-clock time, so a rebuild of the same source
# produces the same binary.
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)

LDFLAGS := -X $(VERSION_PKG).version=$(VERSION) \
           -X $(VERSION_PKG).commit=$(COMMIT) \
           -X $(VERSION_PKG).date=$(DATE)

COVERPROFILE := cover.out

.PHONY: all build test lint cover smoke smoke-down spire-up spire-verify \
        spire-down spire-admin-relay-up spire-admin-relay-down \
        sigstore-up sigstore-verify sigstore-down \
        innsegl-up innsegl-verify innsegl-canary innsegl-demo innsegl-init \
        innsegl-verify-commit innsegl-down innsegl-purge innsegl-backup \
        innsegl-stack-clean innsegl-up-here verify-branch verify-branch-selftest clean

all: build test lint

## build: compile the single innsegl binary
build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

## test: run the full suite with the race detector
test:
	go test ./... -race

## lint: vet and golangci-lint
lint:
	go vet ./...
	golangci-lint run

## cover: write a coverage profile and print the per-function summary
cover:
	go test ./... -covermode=atomic -coverprofile=$(COVERPROFILE)
	go tool cover -func=$(COVERPROFILE)

## spire-up: boot the reference SPIRE stack and create its bootstrap entries
spire-up:
	docker compose -f deploy/compose/spire.yml up -d
	deploy/compose/spire/register.sh

## spire-verify: prove the SPIRE stack issues an SVID for an agent run
spire-verify:
	deploy/compose/spire/verify.sh

## spire-down: tear the SPIRE stack down, volumes included
spire-down:
	docker compose -f deploy/compose/spire.yml --profile verify down -v

# ---------------------------------------------------------------------------
# The admin relay (RM-097, #156). OFF unless asked for: see spire.yml's
# spire-admin-relay service comment and runbooks/spire-admin-access.md for
# what it exposes, for how long, and the two other options this issue tried.
# ---------------------------------------------------------------------------

## spire-admin-relay-up: publish the SPIRE admin API to 127.0.0.1 (off by default)
spire-admin-relay-up:
	docker compose -f deploy/compose/spire.yml --profile adminrelay up -d spire-admin-relay

## spire-admin-relay-down: remove the admin relay — always run this when done
spire-admin-relay-down:
	docker compose -f deploy/compose/spire.yml --profile adminrelay rm --force --stop spire-admin-relay
	docker network rm innsegl-spire-admin-relay >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Self-hosted Sigstore (RM-030, #38). ADR-0010 made this the shipped default,
# not a CI-only convenience.
#
# INNSEGL_SPIRE_JWT_ISSUER is passed to BOTH compose files, and that is the
# whole reason these targets exist rather than a bare `docker compose up`.
# Fulcio believes exactly one issuer; spire-server stamps exactly one `iss`
# claim; spire-oidc advertises exactly one discovery document. All three read
# this variable, and spire.yml's own default (https://oidc.innsegl.dev) is an
# endpoint ADR-0010 decided is never stood up. Setting it in one place is what
# stops the two stacks booting in disagreement.
# ---------------------------------------------------------------------------
INNSEGL_SPIRE_JWT_ISSUER ?= http://spire-oidc:8080
# The tag deploy/compose/innsegl.yml builds and register.sh registers.
INNSEGL_IMAGE ?= innsegl:local

## sigstore-up: boot SPIRE and the local Fulcio/Rekor pair, wired to each other
sigstore-up:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  docker compose -f deploy/compose/spire.yml up -d
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  deploy/compose/spire/register.sh
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  docker compose -f deploy/compose/sigstore.yml up -d

## sigstore-verify: obtain a real Fulcio certificate for a real JWT-SVID
sigstore-verify:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  deploy/compose/sigstore/verify.sh

## sigstore-down: tear the Sigstore stack down, volumes included
sigstore-down:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  docker compose -f deploy/compose/sigstore.yml down -v

# ---------------------------------------------------------------------------
# The fresh-clone contract (RM-054, #62).
#
# `make smoke` is not a convenience target. VERSIONING.md and doc 08 put the
# compose reference stack and this command inside the COMPATIBILITY SURFACE:
# if `make smoke` from the previous minor's README fails on a new minor, that
# is a breaking change misfiled as a minor and the release is blocked. Renaming
# this target, or changing what it runs, is a release decision.
#
# It runs OPS-004, which boots the reference stack from a copy of the
# repository's tracked-and-not-ignored files, runs the demo agent against the
# MCP server over the real transport, and then verifies the resulting commit
# from a container with the ledger network detached — VER-001's independence
# property, demonstrated on first contact with the project.
#
# IT OWNS THE SHIPPED COMPOSE PROJECTS FOR THE LENGTH OF A RUN. To boot from
# nothing it first takes `innsegl-spire` and `innsegl-sigstore` down WITH THEIR
# VOLUMES, and it does so again at the end. A stack you brought up with
# `make sigstore-up` will be removed. That is what "fresh clone" means, and it
# is said here rather than discovered.
#
# Takes a few minutes and needs Docker, git and a Go toolchain. Set
# INNSEGL_TEST_KEEP_STACK=1 to leave everything running afterwards for
# inspection; `make smoke-down` then removes it.
# ---------------------------------------------------------------------------

## smoke: the fresh-clone contract — boot, run the demo agent, verify detached
smoke: innsegl-stack-clean
	go test ./test/smoke -run TestOPS004 -count=1 -v -timeout 40m

# `make smoke` owns the shipped compose projects for the length of a run, and
# since RM-076 (#109) there are THREE of them rather than two.
#
# MEASURED, and it is why this prerequisite exists: `innsegl-mcp` mounts
# spire.yml's Workload API socket volume, because doc 05 §1 makes it an
# attested workload. A container holding that volume — running or merely
# stopped — makes the SPIRE project's `down -v` unable to remove it, and
# OPS-004 then fails, correctly and confusingly:
#
#   volumes from a previous run survived `down -v`:
#   [innsegl-spire_spire-agent-socket]
#
# OPS-004 itself removes only the two projects it knows about, and it is
# test/smoke's file. Removing the third here is what keeps `make smoke` the one
# command an adopter can always run — the promise doc 08 measures a release
# against. Errors are ignored: on a machine with no Docker, or with no innsegl
# stack, there is nothing to remove and that is not a failure.
innsegl-stack-clean:
	-@INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_SPIRE_PARENT_ID=unset \
	  $(INNSEGL_COMPOSE) --profile demo --profile canary down -v \
	  --remove-orphans >/dev/null 2>&1 || true

## smoke-down: remove what a kept `make smoke` stack left behind
smoke-down: innsegl-stack-clean
	-docker rm --force --volumes innsegl-smoke-mcp innsegl-smoke-ledger-relay innsegl-smoke-postgres
	-docker network rm innsegl-smoke-ledger
	-INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  docker compose -f deploy/compose/sigstore.yml down -v
	-docker compose -f deploy/compose/spire.yml --profile verify down -v

# ---------------------------------------------------------------------------
# The components this project IS (RM-076, #109).
#
# doc 05 §1 lists twelve services. spire.yml and sigstore.yml are the five
# dependency rows; innsegl.yml is the other seven — postgres, minio, the MCP,
# the reconciler, the sealer, the dashboard and the demo agent — and until #109
# none of them existed as a compose service.
#
# These targets sit on top of the sigstore ones rather than replacing them: the
# innsegl stack attaches to networks and a volume the other two own, so it
# cannot be brought up on its own and says so if you try.
# ---------------------------------------------------------------------------

INNSEGL_COMPOSE := docker compose -f deploy/compose/innsegl.yml

# The repository the demo agent commits into, as doc 02 §5 spells a repo: an
# identifier, resolved beneath the deployment's workspace root.
DEMO_REPO ?= github.com/innsegl-demo/scratch

## innsegl-up: build the images, register the MCP, and boot the seven rows
innsegl-up: sigstore-up
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' $(INNSEGL_COMPOSE) build
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  deploy/compose/spire/register.sh
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' $(INNSEGL_COMPOSE) up -d

# ---------------------------------------------------------------------------
# innsegl-up-here: the stack, signing in THIS working tree.
#
# Without it, sign_commit resolves a repository beneath the MCP's own empty
# workspace volume, so signing one commit meant copying the repository in,
# staging there, calling the tool, and tarring .git back out. Four of seven
# steps were moving files between two copies of one repository.
#
# REPO and REPO_PATH default to this checkout, read from git rather than
# assumed: the identifier comes from `origin`, so a fork or a rename is
# followed instead of hardcoded.
#
# Read deploy/compose/innsegl.workrepo.yml before using it. It gives the MCP
# write access to the tree you are editing, which is a deliberate choice.
# ---------------------------------------------------------------------------
# The sed delimiter is `|` and not `#`, and that is the whole trick: `#` starts
# a comment in a Makefile even inside $(shell ...), so make never sees the
# closing parenthesis and reports "unterminated call to function `shell'" from
# a line that looks perfectly balanced. Escaped parentheses are avoided for the
# same class of reason -- make counts them.
#
# git@host:org/name.git and https://host/org/name.git both become host/org/name.
REPO_PATH ?= $(shell git rev-parse --show-toplevel)
REPO      ?= $(shell git remote get-url origin 2>/dev/null | sed -e 's|^git@||' -e 's|^https://||' -e 's|^http://||' -e 's|:|/|' -e 's|\.git$$||')

## innsegl-up-here: bring the stack up signing in this working tree, not a copy
innsegl-up-here: sigstore-up
	@test -n "$(REPO)" || { echo 'innsegl-up-here: no origin remote; pass REPO=host/org/name'; exit 2; }
	@echo "signing in $(REPO_PATH)  as  $(REPO)"
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' $(INNSEGL_COMPOSE) build
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  deploy/compose/spire/register.sh
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_REPO_PATH='$(REPO_PATH)' INNSEGL_REPO_ID='$(REPO)' \
	  $(INNSEGL_COMPOSE) -f deploy/compose/innsegl.workrepo.yml up -d

## innsegl-verify: ask the server what the MCP's database credential can do
#
# doc 05 §1 requires a role that appends and cannot delete. This does not read
# the GRANTs, it attempts the writes and classifies the refusals by SQLSTATE —
# see deploy/compose/innsegl/verify-role.sh for why a check that asked "did it
# fail?" would pass the database owner. It writes nothing: every probe runs in
# a transaction that is rolled back.
innsegl-verify:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_COMPOSE) run --rm --entrypoint sh innsegl-db-init \
	  /innsegl/init/verify-role.sh

## innsegl-canary: SEG-005 — prove the object store refuses to delete a segment
innsegl-canary:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_COMPOSE) --profile canary run --rm innsegl-canary

## innsegl-demo: register an identity, sign a commit under it, retire it
innsegl-demo:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_COMPOSE) --profile demo run --rm demo-agent

## innsegl-init: run `innsegl init` as a one-shot workload on the admin network
#
# RM-097 (#156), option 2. REPO=<host path> is required — it is bind-mounted
# read-write at /target, because the repository `init` sets up is the
# operator's, not this deployment's. ARGS carries the rest of `innsegl init`'s
# own flags verbatim (-trust-root, -gitsign-path, the identity questions —
# all yours to answer; nothing here defaults -trust-root for you). See the
# innsegl-init service comment in innsegl.yml and
# runbooks/spire-admin-access.md for what this costs.
#
#   make innsegl-init REPO=/path/to/repo ARGS='-trust-root self-hosted \
#     -gitsign-path /usr/local/bin/gitsign -non-interactive -identity-mode pseudonymous'
innsegl-init:
	@test -n "$(REPO)" || { \
	  echo "usage: make innsegl-init REPO=/path/to/repo ARGS='[innsegl init flags]'"; \
	  exit 2; }
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_COMPOSE) --profile init run --rm \
	  --volume '$(REPO)':/target \
	  innsegl-init init -repo /target $(ARGS)

## innsegl-verify-commit: verify a commit with NO route to the ledger
#
# COMMIT=<sha> is required; `make innsegl-demo` prints the one it just signed.
#
# This is VER-001's independence property, run the way doc 05 §1's smoke
# describes it: a container joined ONLY to the Sigstore stack's published
# network, holding a read-only copy of the working tree and no database
# credential of any kind. It is on none of the three ledger networks, so the
# ledger is not merely unused — it is unreachable.
innsegl-verify-commit:
	@test -n "$(COMMIT)" || { \
	  echo 'usage: make innsegl-verify-commit COMMIT=<sha> [DEMO_REPO=host/org/name]'; \
	  exit 2; }
	docker run --rm \
	  --network innsegl-sigstore-published \
	  --user 1000:1000 \
	  --volume innsegl-core_innsegl-workspace:/work:ro \
	  --env INNSEGL_FULCIO_URL=http://fulcio:5555 \
	  --env INNSEGL_REKOR_URL=http://rekor:3000 \
	  --env INNSEGL_OIDC_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_IMAGE) verify $(COMMIT) -repo /work/$(DEMO_REPO)

## innsegl-down: stop the innsegl stack, keeping the ledger and the segments
# No -v, and that is the whole point. The ledger's event bodies — agent_type,
# task_ref, run_id, every tool_call — live in Postgres and NOWHERE ELSE.
# runbooks/index-rebuild.md §0 is explicit: a sealed segment adjudicates a
# backup, it does not supply one, and "there is no rebuild-from-segments-alone".
# So `down -v` here does not stop a deployment, it destroys the only copy of
# what the agents actually did. What survives is attribution — every commit
# still verifies from git, Fulcio and Rekor — and not the history behind it.
#
# Use innsegl-purge when destroying the data is what you mean.
innsegl-down:
	-INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_SPIRE_PARENT_ID=unset \
	  $(INNSEGL_COMPOSE) --profile demo --profile canary down

## innsegl-purge: tear the innsegl stack down AND delete its data volumes
# Everything innsegl-down's comment says will happen, on purpose.
innsegl-purge:
	-INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_SPIRE_PARENT_ID=unset \
	  $(INNSEGL_COMPOSE) --profile demo --profile canary down -v

# ---------------------------------------------------------------------------
# The ledger backup (issue #160, RM-099).
#
# runbooks/index-rebuild.md §0: losing Postgres loses the event bodies -- the
# agent_type, task_ref, run_id and every tool_call a sealed segment cannot
# give back -- and nothing else in this repository holds a second copy. This
# is why innsegl-down (above) takes the stack down WITHOUT -v: a backup is the
# only other thing standing between an operator and permanent loss, and
# nothing shipped here took one before now.
#
# scripts/backup-ledger.sh does not call itself done on "pg_dump exited 0".
# It restores the dump into a throwaway database in the same container and
# checks the restored chain against the sealed segments with
# runbooks/verify-rebuilt-index.sh before writing anything to
# $(INNSEGL_BACKUP_DIR) (default ./backups) -- the adjudication
# runbooks/index-rebuild.md §0 describes for a restore, run here at backup
# time instead. See that script's header for the exit-status contract and
# scripts/backup-ledger-selftest.sh for BAK-001..004, which prove it red on a
# chain that disagrees with a sealed segment and green on one that matches.
# ---------------------------------------------------------------------------
INNSEGL_BACKUP_DIR ?= backups

## innsegl-backup: pg_dump the ledger and verify it against the sealed segments
innsegl-backup:
	INNSEGL_BACKUP_DIR='$(INNSEGL_BACKUP_DIR)' scripts/backup-ledger.sh --out '$(INNSEGL_BACKUP_DIR)'

# ---------------------------------------------------------------------------
# The merge gate for agent-signed commits (#173, RM-108).
#
# Until this existed, `innsegl verify` was a command nobody ran: agents signed
# commits, Rekor logged them, and no merge path checked one. The decision on
# #173 is that main does not have to carry signatures -- squash-merge detaches
# them, and that is accepted -- because verification happens HERE, before the
# merge, while the deployment that issued the identity is still reachable.
#
# It runs locally and not in CI on purpose: commits signed by a local
# deployment are logged in that deployment's Rekor, which a GitHub runner
# cannot reach. A gate that returned "inconclusive" on every commit forever
# would be an absent gate that looks present.
#
# Exit statuses are cmd/innsegl/verify.go's: 3 an attribution claim does not
# hold, 4 Fulcio or Rekor unreachable so nothing was proved either way. 4 fails
# the gate too -- doc 06 P2 and AB-08 forbid reading "could not check" as
# "checked" -- and the remedy is `make innsegl-up` and run it again.
# ---------------------------------------------------------------------------

# The compose default, so the two targets below resolve to a real URL when
# nothing is exported. Without it $(INNSEGL_REKOR_PORT) is empty, the URL is
# `http://127.0.0.1:` and the gate returns 4 for a reason that has nothing to
# do with the commits -- honest, since 4 is inconclusive rather than green, but
# a poor thing to hand someone running this for the first time. Override it the
# same way the runbook does when 3000 is taken.
INNSEGL_REKOR_PORT ?= 3000

## verify-branch: verify every agent-signed commit on this branch before merging
verify-branch:
	INNSEGL_FULCIO_URL='$(or $(INNSEGL_FULCIO_URL),http://127.0.0.1:5555)' \
	  INNSEGL_REKOR_URL='$(or $(INNSEGL_REKOR_URL),http://127.0.0.1:$(INNSEGL_REKOR_PORT))' \
	  scripts/verify-branch.sh $(BASE)

## verify-branch-selftest: the gate, watched failing -- green, forged, unreachable
verify-branch-selftest:
	INNSEGL_FULCIO_URL='$(or $(INNSEGL_FULCIO_URL),http://127.0.0.1:5555)' \
	  INNSEGL_REKOR_URL='$(or $(INNSEGL_REKOR_URL),http://127.0.0.1:$(INNSEGL_REKOR_PORT))' \
	  scripts/verify-branch-selftest.sh

## clean: remove build and coverage artefacts
clean:
	rm -f $(BINARY) $(COVERPROFILE)
