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
        spire-down sigstore-up sigstore-verify sigstore-down clean

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
smoke:
	go test ./test/smoke -run TestOPS004 -count=1 -v -timeout 40m

## smoke-down: remove what a kept `make smoke` stack left behind
smoke-down:
	-docker rm --force --volumes innsegl-smoke-mcp innsegl-smoke-postgres
	-docker network rm innsegl-smoke-ledger
	-INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  docker compose -f deploy/compose/sigstore.yml down -v
	-docker compose -f deploy/compose/spire.yml --profile verify down -v

## clean: remove build and coverage artefacts
clean:
	rm -f $(BINARY) $(COVERPROFILE)
