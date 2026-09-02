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
        spire-down sigstore-up sigstore-verify sigstore-down \
        innsegl-up innsegl-verify innsegl-canary innsegl-demo \
        innsegl-verify-commit innsegl-down innsegl-stack-clean clean

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

## innsegl-down: tear the innsegl stack down, volumes included
innsegl-down:
	-INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_SPIRE_PARENT_ID=unset \
	  $(INNSEGL_COMPOSE) --profile demo --profile canary down -v

## clean: remove build and coverage artefacts
clean:
	rm -f $(BINARY) $(COVERPROFILE)
