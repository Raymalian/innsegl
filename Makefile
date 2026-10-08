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

.PHONY: all build test test-clean lint cover smoke smoke-down spire-up spire-verify \
        spire-down spire-admin-relay-up spire-admin-relay-down \
        sigstore-up rekor-log-up rekor-index-ready sigstore-verify sigstore-down rekor-tlog-id rekor-reindex \
        innsegl-verify innsegl-canary innsegl-demo innsegl-init \
        innsegl-verify-commit innsegl-down innsegl-purge innsegl-backup \
        innsegl-trust-volumes innsegl-ca-custody-init innsegl-ca-rotate innsegl-ca-rollback \
        fulcio-file-ca-up test-ids ca-custody-up ca-custody-volumes ca-custody-ready \
        ca-custody-stage ca-custody-switch ca-custody-back ca-custody-restore \
        innsegl-stack-clean innsegl-up-here verify-branch \
        install-hooks \
        verify-branch-selftest start backup-freshness update innsegl-here-services link clean \
        image-bundle dev-stack stack-announce

all: build test lint

## build: compile the single innsegl binary
build:
	go build -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

## test: run the full suite with the race detector
#
# WHAT "THE WHOLE SUITE" IS, ASKED RATHER THAN ASSUMED — RM-170 (#275). This was
# `go test ./...`, and `./...` reaches test/failure, which mints a new
# transparency-log tree, and test/smoke, which ends its teardown in
# `docker compose down -v`. Five call sites each decided that independently and
# three of them ran it against a live deployment inside two days.
#
# scripts/test-suite.sh is the single place that decides, and `run` is it doing
# the whole job: answer the question, refuse what must be refused, then run. On
# a host with no deployment the answer is `./...` and nothing changes.
test:
	@scripts/test-suite.sh run -race

## lint: vet and golangci-lint
lint:
	go vet ./...
	golangci-lint run

## cover: write a coverage profile and print the per-function summary
# Same answer, same one place — see the note on `test` above.
cover:
	@scripts/test-suite.sh run -covermode=atomic -coverprofile=$(COVERPROFILE)
	go tool cover -func=$(COVERPROFILE)

# ---------------------------------------------------------------------------
# THE DURABLE TRUST ROOT (doc 05 §2; OPS-031..OPS-033).
#
# On 2026-09-16 a teardown with volumes removed, in one command, took the
# ledger from 19,595 chain positions to 60 and the transparency log from 525
# entries to 3, and minted a new Fulcio CA key and a new Rekor signing key.
# Every commit signed the previous day stopped verifying — the signature is
# intact and the trailer still matches the certificate; the CA that issued it
# and the log that recorded it are gone, and there is no repair. Four merged
# branches had to be re-signed from scratch to pass the merge gate. It happened
# twice the same day.
#
# The rule that follows is one sentence: THE TRUST ROOT MUST NOT LIVE WHERE THE
# TEARDOWN REACHES. Two lines below are what puts it out of reach.
#
# INNSEGL_TRUST_ENV names the four volumes and turns on their external
# declaration, so every compose invocation in this file resolves them to
# volumes DECLARED OUTSIDE the project: `down -v` can only detach them.
# The names come from the script rather than being repeated here, because a
# second copy of a volume name is a second thing that goes stale, and the one
# it goes stale against is a CA key.
#
# GUARD stands in front of every teardown. It refuses to remove a volume
# holding a key or the chain, names what it would have destroyed, and takes
# INNSEGL_DESTROY_TRUST_ROOT=<volume> from an operator who means it.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# LIVE OR DEV (RM-293, #469; ADR-0072; OPS-129).
#
# A machine that develops innsegl runs a stack too, and it ran it under the
# live names and the live trust volumes: a commit it signed carried a
# certificate from whatever CA key `innsegl-trust-fulcio-pki` held there, and
# nothing marked the stack as dev. scripts/stack-mode.sh decides, from an
# explicit marker only (`make dev-stack`, or INNSEGL_STACK=dev); no marker is
# live, and live is byte-for-byte what it was — every variable below expands
# to the text it always had.
#
# In dev, `env` is exported: the innsegl-dev name prefix the host-side scripts
# build container names from, the innsegl-dev-trust volume prefix, and host
# folders under $HOME/.innsegl/dev. The three compose file lists gain the
# deploy/compose/dev/ overlays, which rename projects, containers and networks.
#
# $(shell) is handed the prefixes by name, not by export: make before 4.4 does
# not pass exported variables to $(shell), and macOS ships 3.81.
# ---------------------------------------------------------------------------
INNSEGL_STACK_MODE := $(shell scripts/stack-mode.sh mode)
ifeq ($(filter dev live,$(INNSEGL_STACK_MODE)),)
$(error scripts/stack-mode.sh could not say whether this stack is dev or live; see above)
endif
$(foreach kv,$(shell scripts/stack-mode.sh env),$(eval export $(kv)))
ifeq ($(INNSEGL_STACK_MODE),dev)
unexport INNSEGL_TRUST_LEGACY_PREFIX
DEV_OVERLAY = -f deploy/compose/dev/$(1)
endif
STACK_PREFIX   := $(or $(INNSEGL_STACK_PREFIX),innsegl)
STACK_SHELL_ENV := INNSEGL_STACK_PREFIX='$(INNSEGL_STACK_PREFIX)' INNSEGL_TRUST_VOLUME_PREFIX='$(INNSEGL_TRUST_VOLUME_PREFIX)'
SPIRE_FILES    := -f deploy/compose/spire.yml$(if $(DEV_OVERLAY), $(call DEV_OVERLAY,spire.yml))
SIGSTORE_FILES := -f deploy/compose/sigstore.yml$(if $(DEV_OVERLAY), $(call DEV_OVERLAY,sigstore.yml))

# ADR-0076 (#533): CA key custody, unlocked by the operator's machine. OFF
# unless the compose .env says INNSEGL_CA_CUSTODY=on, so the shipped default is
# the file CA (OPS-051). On, the core runs with innsegl.custody.yml, and the
# store and its custodian run under sigstore.keycustody.yml. Fulcio itself
# moves onto the store only through `make innsegl-ca-rotate TO=custody`, which
# ends the file CA's era in the trust history; until then bring-up leaves it on
# the file CA and says so (OPS-149).
COMPOSE_ENV_FILE ?= deploy/compose/.env
CA_CUSTODY := $(shell grep -qsx 'INNSEGL_CA_CUSTODY=on' '$(COMPOSE_ENV_FILE)' && echo on)
INNSEGL_FILES  := -f deploy/compose/innsegl.yml$(if $(DEV_OVERLAY), $(call DEV_OVERLAY,innsegl.yml))$(if $(CA_CUSTODY), -f deploy/compose/innsegl.custody.yml)

INNSEGL_TRUST_ENV := $(shell $(STACK_SHELL_ENV) deploy/compose/trust-volumes.sh env | tr '\n' ' ')
GUARD             := scripts/teardown-guard.sh

## dev-stack: mark this repository's stack as a DEVELOPMENT stack, once
##   (its own names, its own trust root, loopback only; ADR-0072)
dev-stack:
	@scripts/stack-mode.sh mark-dev

## innsegl-trust-volumes: create the four volumes the trust root lives in
innsegl-trust-volumes:
	deploy/compose/trust-volumes.sh ensure

## spire-up: boot the reference SPIRE stack and create its bootstrap entries
spire-up:
	docker compose $(SPIRE_FILES) up -d
	deploy/compose/spire/register.sh

## spire-verify: prove the SPIRE stack issues an SVID for an agent run
spire-verify:
	deploy/compose/spire/verify.sh

## spire-down: tear the SPIRE stack down, volumes included
spire-down:
	$(GUARD) docker compose $(SPIRE_FILES) --profile verify down -v

# ---------------------------------------------------------------------------
# The admin relay (RM-097, #156). OFF unless asked for: see spire.yml's
# spire-admin-relay service comment and runbooks/spire-admin-access.md for
# what it exposes, for how long, and the two other options this issue tried.
# ---------------------------------------------------------------------------

## spire-admin-relay-up: publish the SPIRE admin API to 127.0.0.1 (off by default)
spire-admin-relay-up:
	docker compose $(SPIRE_FILES) --profile adminrelay up -d spire-admin-relay

## spire-admin-relay-down: remove the admin relay — always run this when done
spire-admin-relay-down:
	docker compose $(SPIRE_FILES) --profile adminrelay rm --force --stop spire-admin-relay
	docker network rm $(STACK_PREFIX)-spire-admin-relay >/dev/null 2>&1 || true

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

# WHICH TREE REKOR SERVES, remembered between boots.
#
# rekor mints a NEW Trillian tree whenever tlog_id is 0, so a restart moved the
# log to an empty tree and left every earlier entry stranded in the database --
# three times in two days, 50 entries. sigstore.yml carries the measurement.
#
# The id is written to a gitignored file on first boot and passed back in on
# every boot after that. A fresh clone has no file, passes 0, gets a tree, and
# records it; there is nothing to do by hand.
# RESOLVED AGAINST THE REPOSITORY, NOT THE TREE THIS RAN FROM (RM-150, #242).
# The pin is gitignored, so a git worktree is a checkout that does not have it —
# and the fallback for "no pin" is 0, which is the value that means MINT A NEW
# TREE. Bring-up from a worktree therefore re-pointed Rekor at an empty log:
# measured 2026-09-16, 74 entries became 1 and every commit ever signed answered
# `unavailable`. Nothing was destroyed and everything stopped being findable,
# which reads the same from outside.
REKOR_TLOG_FILE = $(shell $(STACK_SHELL_ENV) scripts/rekor-tlog-pin.sh path 2>/dev/null || echo deploy/compose/.rekor-tlog-id)
INNSEGL_REKOR_TLOG_ID ?= $(shell $(STACK_SHELL_ENV) scripts/rekor-tlog-pin.sh read 2>/dev/null || echo 0)

## rekor-tlog-id: print the tree rekor is serving and pin it for later boots
rekor-tlog-id:
	@scripts/rekor-tlog-pin.sh record http://127.0.0.1:$(INNSEGL_REKOR_PORT)

## sigstore-up: boot SPIRE and the local Fulcio/Rekor pair, wired to each other
#
# The trust volumes are ensured FIRST and not as a convenience: compose will
# not create an external volume, so a machine that has never run this needs
# them made before anything is brought up. `ensure` is a no-op on the second
# run and refuses rather than adopt a set stamped for another deployment.
sigstore-up: innsegl-trust-volumes
	@# RULE 1 above puts the pin back where a worktree can find it. This is rule
	@# 2, and it is the one that covers the CLASS: any way of losing the pin — a
	@# `git clean -x`, a clone beside an existing deployment — puts 0 back in
	@# front of a live log. Minting is only ever right when there is no log yet.
	@test -n '$(INNSEGL_REKOR_ALLOW_NEW_TREE)' || scripts/rekor-tlog-pin.sh guard
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  docker compose $(SPIRE_FILES) up -d
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  deploy/compose/spire/register.sh
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_REKOR_TLOG_ID='$(INNSEGL_REKOR_TLOG_ID)' \
	  $(INNSEGL_TRUST_ENV) docker compose $(SIGSTORE_FILES) up -d$(if $(CA_CUSTODY), $(SIGSTORE_UP_EXCEPT_FULCIO))
	$(if $(CA_CUSTODY),@$(MAKE) --no-print-directory ca-custody-up)
	@$(MAKE) --no-print-directory rekor-index-ready

# Both this and innsegl-here-services ensure the trust volumes first: compose
# will not create an external volume, so a release that adds one broke the next
# `make update` on an existing host (#533).
# rekor-log-up: the log's own services brought up again, for `make update`.
# Compose recreates only what changed, so on most updates this does nothing;
# when sigstore.yml changed the log (#451 did) it is how the change reaches a
# running host. Fulcio is NOT named: on a host that runs it under
# sigstore.keycustody.yml, an `up` of fulcio from sigstore.yml alone would
# put the file CA back. `make start` brings Fulcio up as it always has.
rekor-log-up: innsegl-trust-volumes
	@test -n '$(INNSEGL_REKOR_ALLOW_NEW_TREE)' || scripts/rekor-tlog-pin.sh guard
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_REKOR_TLOG_ID='$(INNSEGL_REKOR_TLOG_ID)' \
	  $(INNSEGL_TRUST_ENV) docker compose $(SIGSTORE_FILES) up -d trillian-db trillian-log-server trillian-log-signer rekor
	@$(MAKE) --no-print-directory rekor-index-ready

# fulcio-file-ca-up: Fulcio brought up again from sigstore.yml, for
# `make update`, on a host that runs the file CA. #533 changed how Fulcio
# gets its CA key's password: from serve.yaml, which the bootstrap writes,
# instead of a command-line value. The bootstrap runs on every update (rekor
# depends on it), and may re-lock a key that was on the old public default;
# a Fulcio left on its old command line would then fail on its next restart.
# So the update recreates it. Compose recreates only what changed, so on most
# updates this does nothing. A host that runs Fulcio under
# sigstore.keycustody.yml is left alone: an `up` of fulcio from sigstore.yml
# alone would put the file CA back there (see rekor-log-up).
fulcio-file-ca-up: innsegl-trust-volumes
	$(if $(CA_CUSTODY),@$(MAKE) --no-print-directory ca-custody-up; exit 0)
	@cmd=$$(docker inspect -f '{{json .Config.Cmd}}' $(STACK_PREFIX)-sigstore-fulcio 2>/dev/null); \
	 case "$$cmd" in \
	   *--ca=kmsca*) echo "make update: Fulcio runs under key custody; left as it is" ;; \
	   *) INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	        INNSEGL_REKOR_TLOG_ID='$(INNSEGL_REKOR_TLOG_ID)' \
	        $(INNSEGL_TRUST_ENV) docker compose $(SIGSTORE_FILES) up -d fulcio ;; \
	 esac

# rekor-index-ready: the log pinned and its search index complete, before
# anything that verifies starts. sigstore-up and rekor-log-up both end here.
#
# The old rekor-redis container (#451) is removed BY NAME. `up` leaves a
# container whose service is gone running, and --remove-orphans is NOT the
# answer: innsegl-ca-store is a service of this same compose project,
# declared in sigstore.keycustody.yml, and an `up` of sigstore.yml alone with
# --remove-orphans would remove the CA store on every host using key custody.
# Its volume is left; nothing mounts it.
#
# THE SEARCH INDEX IS NOT REBUILT AT EVERY START, and that is the point of
# #451. The index was Redis on a volume of its own, `down -v` removed it while
# the log kept every entry, and `innsegl verify` then accused good commits
# (OPS-036), so bring-up walked the whole log every time. Since ADR-0010's
# 2026-10-05 amendment it is a table in trillian-db, on the trust volume the
# log lives on. --if-behind asks the index how many of this tree's entries it
# holds and backfills only when that is fewer than the log: ONCE on a host
# whose log predates the move, and never after. It FAILS the bring-up when it
# cannot finish, because the core must not start verifying against an index
# that would call good commits never logged.
rekor-index-ready:
	@docker rm -f $(STACK_PREFIX)-sigstore-rekor-redis >/dev/null 2>&1 || true
	@# Waits for the log, and a bring-up that cannot pin it FAILS (#345): an
	@# unpinned log is refused by the guard on the next start.
	@$(MAKE) --no-print-directory rekor-tlog-id
	@INNSEGL_REKOR_URL='$(or $(INNSEGL_REKOR_URL),http://127.0.0.1:$(INNSEGL_REKOR_PORT))' \
	  scripts/rekor-reindex.sh --if-behind

## rekor-reindex: backfill Rekor's search index from the whole log, always
##   (bring-up does it only when the index is behind; this is the repair)
rekor-reindex:
	@INNSEGL_REKOR_URL='$(or $(INNSEGL_REKOR_URL),http://127.0.0.1:$(INNSEGL_REKOR_PORT))' \
	  scripts/rekor-reindex.sh

## sigstore-verify: obtain a real Fulcio certificate for a real JWT-SVID
sigstore-verify:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  deploy/compose/sigstore/verify.sh

## sigstore-down: tear the Sigstore stack down, volumes included
sigstore-down:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_TRUST_ENV) $(GUARD) docker compose $(SIGSTORE_FILES) down -v

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
#
# THE GUARD RUNS FIRST, AND IT IS INSIDE THE RECIPE RATHER THAN A PREREQUISITE —
# RM-170 (#275). `innsegl-stack-clean` is itself the `down -v` that #168 is
# about, so it must not run before the question is asked; make orders
# prerequisites left to right only while it is not running in parallel, and a
# gate that holds on a good day is the shape of defect this repository keeps
# finding. A sub-make is the ordering that does not depend on -j.
smoke:
	@scripts/test-suite.sh guard test/smoke
	@$(MAKE) --no-print-directory innsegl-stack-clean
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
	  $(INNSEGL_TRUST_ENV) $(GUARD) docker compose -f deploy/compose/innsegl.yml \
	  --profile demo --profile canary down -v \
	  --remove-orphans >/dev/null 2>&1 || true

## smoke-down: remove what a kept `make smoke` stack left behind
smoke-down: innsegl-stack-clean
	-docker rm --force --volumes innsegl-smoke-mcp innsegl-smoke-ledger-relay innsegl-smoke-postgres
	-docker network rm innsegl-smoke-ledger
	-INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_TRUST_ENV) $(GUARD) docker compose -f deploy/compose/sigstore.yml down -v
	-$(GUARD) docker compose -f deploy/compose/spire.yml --profile verify down -v

# ---------------------------------------------------------------------------
# The components this project IS (RM-076, #109).
#
# spire.yml and sigstore.yml are doc 05 §1's dependency rows; innsegl.yml is
# the rest — postgres, the object store, the MCP, the reconciler, the sealer,
# the dashboard (innsegl-api) and the demo agent — and until #109 none of them existed as a
# compose service. The object store is one of those services (#451): one
# process whose S3 layer alone enforces object lock and alone is reachable.
#
# These targets sit on top of the sigstore ones rather than replacing them: the
# innsegl stack attaches to networks and a volume the other two own, so it
# cannot be brought up on its own and says so if you try.
# ---------------------------------------------------------------------------

INNSEGL_COMPOSE := $(INNSEGL_TRUST_ENV) docker compose $(INNSEGL_FILES)

# The repository the demo agent commits into, as doc 02 §5 spells a repo: an
# identifier, resolved beneath the deployment's workspace root.
DEMO_REPO ?= github.com/innsegl-demo/scratch

# ---------------------------------------------------------------------------
# innsegl-up-here: the stack, built from THIS working tree.
#
# The core reads repositories only from its mirror, which clients push to
# (ADR-0065). It mounts no folder of the host's projects: on a core host that
# folder is the core's own disk, not any client's.
#
# REPO defaults to this checkout's identifier, read from git rather than
# assumed: the identifier comes from `origin`, so a fork or a rename is
# followed instead of hardcoded.
# ---------------------------------------------------------------------------
# The sed delimiter is `|` and not `#`, and that is the whole trick: `#` starts
# a comment in a Makefile even inside $(shell ...), so make never sees the
# closing parenthesis and reports "unterminated call to function `shell'" from
# a line that looks perfectly balanced. Escaped parentheses are avoided for the
# same class of reason -- make counts them.
#
# git@host:org/name.git and https://host/org/name.git both become host/org/name.

# INNSEGL_BUILD_SERVICES builds each image the stack runs exactly once. Several
# services share one image, and `compose build` with no names builds and
# unpacks that image once per service (measured: the same image exported
# seven times, about 30s each, on every update). One service per image:
# test/deploy/buildonce_test.go holds this list to the compose file.
# innsegl-api has an image of its own (the runtime plus the built UI, #475),
# so a dashboard change rebuilds and restarts it alone.
INNSEGL_BUILD_SERVICES := innsegl-mcp innsegl-backup innsegl-api

# DEPLOY_COMMIT names what a checkout is: HEAD, with "-dirty" when the
# tracked files differ from it. `make update` records the one it deployed in
# $(DEPLOYED_FILE) and does nothing when the checkout still matches it; a
# dirty tree never matches, so it is always built.
DEPLOY_COMMIT := $(shell git rev-parse --short=12 HEAD 2>/dev/null)$(shell git diff --quiet HEAD -- 2>/dev/null || echo -dirty)
# DEPLOY_STATE is what the marker holds: the commit and a checksum of the
# compose .env, which git does not track. Turning a profile on is a change to
# .env alone, and an update that compared only the commit started nothing
# (OPS-135). COMPOSE_ENV_FILE is set above, beside CA_CUSTODY.
DEPLOY_STATE := $(DEPLOY_COMMIT) env:$(shell if [ -f '$(COMPOSE_ENV_FILE)' ]; then cksum < '$(COMPOSE_ENV_FILE)' | cut -d' ' -f1; else echo none; fi)
DEPLOYED_FILE := .innsegl/deployed-commit$(if $(DEV_OVERLAY),-dev)

# GO_IMAGE_COMMIT stamps the Go image (dev.innsegl.commit): the last commit
# that touched what that image is built from. Stamped with HEAD instead, every
# commit -- a dashboard or README change too -- made a new image, and compose
# restarted every service running it. The Dockerfile copies these paths and
# nothing else; test/deploy/buildonce_test.go holds the two lists together.
GO_IMAGE_INPUTS := cmd internal migrations go.mod go.sum Dockerfile

# No default build attestations. They record the build's own time, so every
# build -- even of unchanged sources, every layer cached -- had a new image
# ID, and compose restarted every service on it. Measured 2026-10-03: two
# compose builds of one commit, two IDs; with this set, one. The images are
# local and never pushed, so the attestation was read by nothing.
export BUILDX_NO_DEFAULT_ATTESTATIONS := 1
GO_IMAGE_COMMIT := $(shell git log -1 --format=%h --abbrev=12 -- $(GO_IMAGE_INPUTS) 2>/dev/null)$(shell git diff --quiet HEAD -- $(GO_IMAGE_INPUTS) 2>/dev/null || echo -dirty)

# The other two images, stamped the same way (ADR-0070). innsegl-api's image is
# the runtime plus the built UI, so it carries GO_IMAGE_COMMIT and this one;
# the ui-build stage copies web/ alone (test/deploy/buildonce_test.go). The
# backup stage copies nothing from the build context.
UI_IMAGE_INPUTS := web Dockerfile
UI_IMAGE_COMMIT := $(shell git log -1 --format=%h --abbrev=12 -- $(UI_IMAGE_INPUTS) 2>/dev/null)$(shell git diff --quiet HEAD -- $(UI_IMAGE_INPUTS) 2>/dev/null || echo -dirty)
BACKUP_IMAGE_INPUTS := Dockerfile
BACKUP_IMAGE_COMMIT := $(shell git log -1 --format=%h --abbrev=12 -- $(BACKUP_IMAGE_INPUTS) 2>/dev/null)$(shell git diff --quiet HEAD -- $(BACKUP_IMAGE_INPUTS) 2>/dev/null || echo -dirty)

# BUILD ONCE, DEPLOY A VERIFIED IMAGE (ADR-0070). `make image-bundle` builds
# the three images on another machine for the deployment host's platform and
# saves them into dist/ as one file with its .sha256. innsegl-here-services
# loads that file instead of building when it is there for this commit, and
# refuses it -- starting nothing -- unless every image carries the commits
# above. INNSEGL_IMAGE_BUNDLE names a file elsewhere.
INNSEGL_IMAGE_PLATFORM ?= linux/amd64
INNSEGL_IMAGE_BUNDLE ?=
IMAGE_BUNDLE_ENV := INNSEGL_DEPLOY_COMMIT='$(DEPLOY_COMMIT)' INNSEGL_GO_IMAGE_COMMIT='$(GO_IMAGE_COMMIT)' INNSEGL_UI_IMAGE_COMMIT='$(UI_IMAGE_COMMIT)' INNSEGL_BACKUP_IMAGE_COMMIT='$(BACKUP_IMAGE_COMMIT)' INNSEGL_IMAGE_INPUTS='$(sort $(GO_IMAGE_INPUTS) $(UI_IMAGE_INPUTS) $(BACKUP_IMAGE_INPUTS))' INNSEGL_IMAGE_BUNDLE='$(INNSEGL_IMAGE_BUNDLE)' INNSEGL_IMAGE_PLATFORM='$(INNSEGL_IMAGE_PLATFORM)'
REPO      ?= $(shell git remote get-url origin 2>/dev/null | sed -e 's|^git@||' -e 's|^https://||' -e 's|^http://||' -e 's|:|/|' -e 's|\.git$$||')

# THE IDENTITY LISTENER, on for this target and not for the shipped default.
#
# innsegl.yml leaves INNSEGL_MCP_ADMIN_LISTEN empty and says why: with the split
# on and nothing registering, no run can be created at all. This target is the
# one where something does register -- the harness hook calls register_agent --
# and without the listener every registration is refused as unreachable:
# honest, and a dead end, because the target that exists to make signing work
# did not start the listener signing needs.
INNSEGL_MCP_ADMIN_LISTEN ?= 0.0.0.0:8090

# THE REAPER IS BACK ON (#180 fixed, 2026-09-09).
#
# It was turned on here for one minute on 2026-09-08 and expired two subagents
# that were alive and working -- 183 and 130 tool calls, last activity in the
# same second it killed them:
#
#   reap at 13:15:52Z: 2 entries in the agent subtree, 0 live, 2 expired
#
# It judged a run by its AGE, and a subagent works for hours on one registration
# and re-registers never. It now asks the ledger whether the run is still doing
# anything and reaps only a run that is past its TTL AND has gone quiet for the
# grace on top (internal/spire/silence.go). SPI-013 holds it to that against a
# real SPIRE and a real ledger: two runs, same agent type, same TTL, registered
# in the same second, both past the same deadline at the sweep -- one appends a
# tool_call and keeps its identity, the other is reaped.
#
# WHY THE SIGNAL CAN BE TRUSTED HERE. What registers a run is also what records
# every tool call it makes: the gateway, from the run's own traffic (ADR-0057,
# ADR-0058). A working run keeps appending, while a run that finished or died
# goes quiet. No traffic means no registration, so there is no run for the
# reaper to get wrong.
#
# It runs inside the MCP, with the sealer and the reconciler: compose's own
# default for INNSEGL_MCP_ALSO is seal,reconcile,reap,gateway (ADR-0056, ADR-0060), and empty
# here leaves that default alone. Set it only for the separate topology.
INNSEGL_MCP_ALSO ?=

# ADR-0047 decision 4, and the reason it is on here.
#
# PR #200 merged on 2026-09-10 by rebase, which is the only strategy `main`
# permits: required_linear_history forbids a merge commit and squash is
# disabled. All fifteen commits were rewritten, every gitsign signature
# destroyed, every Agent-* trailer intact. Nothing recorded the new SHAs,
# because nothing was configured to -- so `main` now carries fifteen commits
# that claim an identity with nothing on the object to back it, and no record
# tying them to the changes that were signed.
#
# Those fifteen cannot be recovered: they were signed before schema 2, so no
# patch_id was ever recorded for them. Everything signed from the cutover
# onwards can be, and this is what does it.
#
# OFF by default since the core reads repositories only from its mirror
# (ADR-0065): a mirror holds the commits clients push and the signed commits
# the core keeps, and no branch until clients push their branches (#465).
# Pointed at `main` it would report the branch unreadable every cycle and
# record nothing. Name a branch here once clients push it.
# Both or neither: the reconciler refuses one without the other, and it runs
# inside the core (test/deploy TestTheRebaseDefaultsAreSetTogether).
INNSEGL_REBASE_BRANCH ?=
INNSEGL_REBASE_REPOS ?=
# RM-104 (#169): where the reconciler finds the retained bodies INSIDE the
# container. innsegl.yml mounts the host path read-only at /harness-log.
# RM-104 (#169). Safe to enable because the check now only COUNTS: it appends
# nothing to the chain and therefore cannot accuse anyone. It was briefly
# enabled while it still appended and wrote 617 findings from 1121 claims —
# every one an honest write whose content a squash, a rebase or a later edit
# had moved. What is worth watching is the corroboration RATE, not any single
# uncorroborated write.
INNSEGL_WRITES_LOG_DIR ?= /harness-log
# The repositories RM-104's check may read, read from the core's mirror. Name
# the repositories agents WORK in: empty falls back to the rebase list, which
# is this repository alone and the wrong set — measured: 0 of 66 tool-call
# runs were in it.
INNSEGL_WRITES_REPOS ?=

## test-clean: remove containers a killed test run left behind
#
# A test package brings up its own Postgres (and sometimes a SPIRE or a
# Sigstore) in TestMain and removes it when the package finishes. A run that is
# KILLED never gets there, and Ctrl-C during a long suite is normal.
#
# Measured 2026-09-10: seven throwaway databases still running, two of them
# fourteen hours old, indistinguishable from a real one except by the random
# name Docker had given them. They are labelled now, so this is one line and it
# cannot touch the deployment -- innsegl-postgres carries no such label.
test-clean:
	@ids="$$(docker ps -aq --filter label=dev.innsegl.test 2>/dev/null)"; \
	if [ -z "$$ids" ]; then echo "test-clean: nothing left behind"; else \
	  echo "test-clean: removing $$(printf '%s\n' "$$ids" | grep -c .) container(s) from killed test runs"; \
	  docker rm --force --volumes $$ids >/dev/null; fi
	@docker network prune -f >/dev/null 2>&1 || true

## innsegl-up-here: bring the stack up, built from this working tree
innsegl-up-here: stack-announce sigstore-up innsegl-here-services

# stack-announce: the one line that says which stack this is, and the refusals
# a dev stack makes before anything starts (ADR-0072). `start` says it first
# itself, so its sub-make does not say it twice.
stack-announce:
	@test -n '$(INNSEGL_STACK_ANNOUNCED)' || scripts/stack-mode.sh announce

# innsegl-here-services: innsegl's own services in THIS working tree, built
# and brought up; the trust services (SPIRE, Fulcio, Rekor) are left as they
# are. innsegl-up-here starts those first; `make update` assumes they run.
#
# --remove-orphans: a service removed from innsegl.yml leaves its container
# running, and compose does not stop it. The old innsegl-dashboard (nginx)
# held the dashboard's ports, so innsegl-api could not bind them (#475). The
# trust services are other compose projects and are not touched.
#
# The images come from a verified bundle when one is there for this commit
# (ADR-0070), and are built here when none is. A bundle that fails its checks
# stops this target before anything starts; it never falls back to a build.
# --no-build: the start that follows uses the images just loaded or built,
# and never builds one of its own.
innsegl-here-services: innsegl-trust-volumes
	@scripts/stack-mode.sh check
	@test -n "$(REPO)" || { echo 'innsegl-up-here: no origin remote; pass REPO=host/org/name'; exit 2; }
	@# The stack's host folders are made here, as the user running make, for
	@# the reason innsegl-backup gives: a bind-mount source that does not exist
	@# is created by the runtime, and on Linux that means owned by root and
	@# unwritable by the uid-1000 services. Measured on a Linux core host
	@# 2026-10-02: the gateway could not write its CA certificate.
	mkdir -p "$${INNSEGL_GATEWAY_CA_HOST_DIR:-$$HOME/.innsegl/ca}" "$${INNSEGL_LOG_DIR:-$$HOME/.innsegl/log}" \
	  "$${INNSEGL_BACKUP_HOST_DIR:-$$HOME/innsegl-backups}"
	@bundle="$$($(IMAGE_BUNDLE_ENV) scripts/image-bundle.sh find)" || exit $$?; \
	 if [ -n "$$bundle" ]; then \
	   $(IMAGE_BUNDLE_ENV) scripts/image-bundle.sh load "$$bundle"; \
	 else \
	   echo "innsegl: no image bundle for $(DEPLOY_COMMIT); building here"; \
	   INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' INNSEGL_COMMIT='$(GO_IMAGE_COMMIT)' INNSEGL_UI_COMMIT='$(UI_IMAGE_COMMIT)' INNSEGL_BACKUP_COMMIT='$(BACKUP_IMAGE_COMMIT)' $(INNSEGL_COMPOSE) build $(INNSEGL_BUILD_SERVICES); \
	 fi
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  deploy/compose/spire/register.sh
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_COMMIT='$(GO_IMAGE_COMMIT)' \
	  INNSEGL_UI_COMMIT='$(UI_IMAGE_COMMIT)' \
	  INNSEGL_BACKUP_COMMIT='$(BACKUP_IMAGE_COMMIT)' \
	  INNSEGL_MCP_ADMIN_LISTEN='$(INNSEGL_MCP_ADMIN_LISTEN)' \
	  INNSEGL_MCP_ALSO='$(INNSEGL_MCP_ALSO)' \
	  INNSEGL_REBASE_BRANCH='$(INNSEGL_REBASE_BRANCH)' \
	  INNSEGL_REBASE_REPOS='$(INNSEGL_REBASE_REPOS)' \
	  INNSEGL_WRITES_LOG_DIR='$(INNSEGL_WRITES_LOG_DIR)' \
	  INNSEGL_WRITES_REPOS='$(INNSEGL_WRITES_REPOS)' \
	  INNSEGL_LOG_DIR='$(INNSEGL_LOG_DIR)' \
	  $(INNSEGL_COMPOSE) up -d --remove-orphans --no-build

# ---------------------------------------------------------------------------
# link: install the commit hook in one repository on this machine.
#
# It is `innsegl link <dir>` (ADR-0059): the repository's prepare-commit-msg
# hook, and nothing else about it. The core needs nothing per repository; a
# repository reaches it when the client pushes it to the mirror (ADR-0065).
# ---------------------------------------------------------------------------

# ===========================================================================
# The two commands.
#
# Everything below this line is one deployment's worth of settings that an
# operator should not have to know about. The targets above are the reference
# stack, documented and unchanged; these are the easy path onto it.
#
#   make start                      bring it up, ready to sign
#   make link DIR=~/Applications/x  install the commit hook in a project
#
# Agents' commits are signed through the gateway (ADR-0059); a human commits
# with plain git.
#
# The opinions baked in here, and each is a real choice rather than a default
# nobody thought about:
#
#   - the admin listener is ON. Without it nothing can register a run, and
#     since RM-105 the model cannot register for itself. A deployment with it
#     off can sign nothing.
#   - the sealer and the reconciler run inside the MCP. That is innsegl.yml's
#     own default (ADR-0056), not a setting of this target.
#   - Rekor's host port is chosen at run time from what is free. 3000 is the
#     compose default and is taken by a great many development servers; the
#     failure is a bind error during bring-up that reads like a broken stack.
# ===========================================================================

## start: bring the whole thing up, ready to sign, with no setup
start:
	@scripts/stack-mode.sh announce
	@port=$$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'); \
	 echo "innsegl: rekor on 127.0.0.1:$$port"; \
	 INNSEGL_REKOR_PORT=$$port \
	 INNSEGL_MCP_ADMIN_LISTEN=0.0.0.0:8090 \
	 INNSEGL_STACK_ANNOUNCED=1 \
	 $(MAKE) --no-print-directory innsegl-up-here
	@echo
	@echo "ready. Next:"
	@echo "   make link DIR=~/Applications/<project>     install the commit hook in a project"
	@# #445, ADR-0062's 2026-10-01 amendment: while no account exists yet,
	@# print the one-time setup link rather than making the operator run the
	@# enrol-code command and build the URL by hand. The script reads the
	@# published address (INNSEGL_BIND, INNSEGL_DASHBOARD_PORT) itself, waits
	@# up to two minutes for innsegl-api, and then stops with one message that
	@# says how to get the link later (RM-325); a failure here never fails start.
	@scripts/setup-link.sh || true
	@# The transparency log's pinned tree is still there; if not, nothing
	@# signed now can be anchored (OPS-034). A fault, so it fails the start. A
	@# host with no pin yet passes. The backup's age is NOT checked here: a
	@# fresh install has no verified backup, and install.sh runs this target.
	@INNSEGL_REKOR_PORT="$${INNSEGL_REKOR_PORT:-$$(scripts/rekor-port.sh)}" scripts/rekor-tlog-health.sh

## backup-freshness: how old is the last VERIFIED backup, and did its host copy land
backup-freshness:
	@scripts/backup-freshness.sh

## update: rebuild and restart innsegl's own services only, for a stack that
##   is already up (`make start` once). SPIRE and Fulcio keep running; the
##   log's services are brought up again, which recreates only what changed
##   in them, and the log's search index is backfilled if it is behind
##   (#451). A code update takes the build and a
##   restart of what changed, not a full start. `docker compose up -d`
##   recreates only the services whose image or settings changed. With a
##   bundle from `make image-bundle` in dist/ for this commit, it loads and
##   checks that instead of building (ADR-0070).
update:
	@scripts/stack-mode.sh check
	@docker ps --format '{{.Names}}' | grep -qx $(STACK_PREFIX)-spire-server && docker ps --format '{{.Names}}' | grep -qx $(STACK_PREFIX)-sigstore-rekor || \
	  { echo "make update: SPIRE or Rekor is not running; run make start"; exit 2; }
	@deployed=$$(cat '$(DEPLOYED_FILE)' 2>/dev/null); \
	 core=$$(docker inspect -f '{{.State.Status}} restarting={{.State.Restarting}}' $(STACK_PREFIX)-mcp 2>/dev/null); \
	 if [ "$$deployed" = "$(DEPLOY_STATE)" ] && [ "$$core" = "running restarting=false" ]; then \
	   echo "make update: already up to date ($(DEPLOY_STATE)); nothing to do"; exit 0; fi; \
	 [ "$$deployed" = "$(DEPLOY_STATE)" ] && echo "make update: the core is $${core:-not there}; starting it again"; \
	 echo "make update: deployed $${deployed:-an unrecorded checkout}, checkout is $(DEPLOY_STATE)"; \
	 $(MAKE) --no-print-directory rekor-log-up && \
	 $(MAKE) --no-print-directory fulcio-file-ca-up && \
	 INNSEGL_MCP_ADMIN_LISTEN=0.0.0.0:8090 $(MAKE) --no-print-directory innsegl-here-services && \
	 mkdir -p "$$(dirname '$(DEPLOYED_FILE)')" && echo '$(DEPLOY_STATE)' > '$(DEPLOYED_FILE)'
	@echo
	@echo "updated: only the services whose image or settings changed were restarted"

## image-bundle: build the images once, here, for the deployment host
##   (INNSEGL_IMAGE_PLATFORM, default linux/amd64), into one file in dist/
##   with its .sha256 (ADR-0070). Refuses a dirty tree. Copy both files to
##   the host's dist/ and run `make update` there: it loads and checks them
##   instead of building.
image-bundle:
	@$(IMAGE_BUNDLE_ENV) scripts/image-bundle.sh create

## link: install the commit hook in a project — make link DIR=~/Applications/foo
# The innsegl binary `link` runs: the one `make build` writes here, the same
# default install.sh uses.
INNSEGL_BIN_PATH ?= $(CURDIR)/$(BINARY)

link:
	@test -n "$(DIR)" || { echo 'link: pass DIR=<path to a git repository>'; exit 2; }
	@d="$$(cd '$(DIR)' && pwd -P)"; \
	 main="$$($(CURDIR)/scripts/repo-main-worktree.sh "$$d" || true)"; \
	 if [ -n "$$main" ] && [ "$$main" != "$$d" ]; then \
	   echo "link: $$d is a linked worktree, not a repository."; \
	   echo "  A worktree shares its repository's hooks, so the hook belongs to the"; \
	   echo "  repository; linking the worktree path names the wrong tree."; \
	   echo "  Link the repository instead:  make link DIR=$$main"; \
	   exit 2; \
	 fi; \
	 '$(INNSEGL_BIN_PATH)' link "$$d"

# ---------------------------------------------------------------------------
# The CA's key custody — rung 3 (RM-147, #238). OPT-IN, and nothing above
# changes because of it: the default stack is the file CA it has always been,
# which is what OPS-051 asserts.
#
# The store starts SEALED and there is no unseal key in this repository. That
# is the design and not a rough edge: a store that unseals itself holds a key
# something on this machine can read, which is the property this rung exists to
# remove. Losing the unseal key loses the CA exactly as losing a key file would
# — the same loss, a different custodian, and the custodian is now a person.
CA_CUSTODY_COMPOSE = -f deploy/compose/sigstore.yml -f deploy/compose/sigstore.keycustody.yml

# Every service of sigstore.yml but Fulcio: with custody on, Fulcio is brought
# up by ca-custody-up, under the overlay or left on the file CA.
SIGSTORE_UP_EXCEPT_FULCIO = sigstore-bootstrap trillian-db trillian-log-server trillian-log-signer rekor

## ca-custody-up: ADR-0076 — the CA key store and its custodian; Fulcio on the
##   store once `make innsegl-ca-rotate TO=custody` has moved it there
ca-custody-up: ca-custody-volumes
	$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) up -d innsegl-ca-store innsegl-ca-custodian
	@cmd=$$(docker inspect -f '{{json .Config.Cmd}}' $(STACK_PREFIX)-sigstore-fulcio 2>/dev/null); \
	 case "$$cmd" in \
	   *--ca=fileca*) echo "ca custody: on in .env, and Fulcio still runs the file CA."; \
	                  echo "  Finish the switch: make innsegl-ca-rotate CONFIRM=rotate TO=custody MODE=retire REASON='CA key custody'"; \
	                  echo "  (runbooks/ca-custody.md). Until then nothing about signing changes." ;; \
	   *) INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	        $(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) up -d innsegl-ca-bootstrap fulcio ;; \
	 esac

## ca-custody-volumes: ADR-0076 — the store's data and the sealed unlock
##   material, trust-root volumes the teardown guard refuses to remove
ca-custody-volumes:
	@for v in innsegl-trust-ca-store innsegl-trust-ca-custody; do \
	   docker volume inspect "$$v" >/dev/null 2>&1 || \
	   docker volume create --label dev.innsegl.trust-root="the CA key store and its sealed unlock material (ADR-0076)" "$$v" >/dev/null || exit 1; \
	 done
	@# The custodian runs as the CA's uid and writes the sealed material here.
	@docker run --rm -v innsegl-trust-ca-custody:/d $(CA_CUSTODY_CHOWN_IMAGE) chown 65532:65532 /d

CA_CUSTODY_CHOWN_IMAGE = alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
# The volume the store's root and Fulcio's issuer config live in under custody.
CA_CUSTODY_KMS_VOLUME = $(STACK_PREFIX)-sigstore_sigstore-fulcio-kms

# The steps `make innsegl-ca-rotate TO=custody` runs (scripts/ca-rotate.sh).
## ca-custody-ready: exit 0 when the store is unlocked and the CA has a token
ca-custody-ready:
	@docker exec innsegl-ca-custodian innsegl ca-custodian ready

## ca-custody-stage: mint the store's root, if there is none, and print it
ca-custody-stage:
	@$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) create --no-recreate innsegl-ca-bootstrap >&2
	@docker run --rm -v $(CA_CUSTODY_KMS_VOLUME):/k $(CA_CUSTODY_CHOWN_IMAGE) chown 65532:65532 /k
	@$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) run --rm --no-deps innsegl-ca-bootstrap >&2
	@docker run --rm -v $(CA_CUSTODY_KMS_VOLUME):/k:ro $(CA_CUSTODY_CHOWN_IMAGE) cat /k/chain.pem

## ca-custody-restore: the store and its sealed material from a trust-key
##   backup extracted with `innsegl trust-backup drill --extract DIR`.
##   FROM=DIR CONFIRM=restore. The store comes back sealed under its original
##   keys; the operator's machine unlocks it (runbooks/ca-custody.md).
ca-custody-restore:
	@test '$(CONFIRM)' = restore || { echo 'ca-custody-restore: set CONFIRM=restore; it replaces the CA key store with the backup'"'"'s'; exit 2; }
	@test -s '$(FROM)/ca-store/store.snap' && test -s '$(FROM)/ca-custody/unlock.age' || \
	  { echo 'ca-custody-restore: FROM must be an extracted backup holding ca-store/store.snap and ca-custody/unlock.age'; exit 2; }
	@# The custodian initialises any new store it finds, so it is stopped first.
	-$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) stop innsegl-ca-custodian innsegl-ca-store
	-$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) rm -f innsegl-ca-custodian innsegl-ca-store
	docker volume rm innsegl-trust-ca-store
	@$(MAKE) --no-print-directory ca-custody-volumes
	docker run --rm -v innsegl-trust-ca-custody:/c -v '$(abspath $(FROM))/ca-custody:/in:ro' $(CA_CUSTODY_CHOWN_IMAGE) \
	  sh -c 'mkdir -p /c/material && cp /in/unlock.age /c/material/unlock.age && chown -R 65532:65532 /c && chmod 0600 /c/material/unlock.age'
	$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) up -d --no-deps innsegl-ca-store
	$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) run --rm --no-deps \
	  -v '$(abspath $(FROM))/ca-store:/restore:ro' innsegl-ca-custodian restore /restore/store.snap
	$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) up -d --no-deps innsegl-ca-custodian
	@echo 'ca-custody-restore: done. Unlock it from the operator'"'"'s machine: innsegl ca-custody unlock'

## ca-custody-switch: Fulcio onto the store
ca-custody-switch:
	@INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) up -d --no-deps fulcio >&2

## ca-custody-back: Fulcio onto the file CA again, which custody left untouched
ca-custody-back:
	@INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_TRUST_ENV) docker compose $(SIGSTORE_FILES) up -d --no-deps fulcio >&2

## innsegl-ca-custody-init: once — start the store and mint its keys
innsegl-ca-custody-init:
	@test '$(INNSEGL_STACK_MODE)' = live || { echo 'innsegl-ca-custody-init: key custody is for a live core; a DEV stack keeps the file CA (ADR-0072)'; exit 2; }
	$(INNSEGL_TRUST_ENV) docker compose $(CA_CUSTODY_COMPOSE) up -d innsegl-ca-store
	@scripts/ca-custody.sh init

## innsegl-ca-rotate: replace the Fulcio CA; the old root stays trusted for what
##   it signed. CONFIRM=rotate MODE=retire|revoke REASON='...'
##   [BACKUP_MAX_AGE_HOURS=N] [TO=custody]. Read runbooks/trust-rotation.md
##   first; TO=custody moves Fulcio onto the CA key store (runbooks/ca-custody.md).
innsegl-ca-rotate:
	@INNSEGL_STACK_PREFIX='$(STACK_PREFIX)' INNSEGL_STACK_MODE='$(INNSEGL_STACK_MODE)' \
	  INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_REKOR_PORT="$${INNSEGL_REKOR_PORT:-$$(scripts/rekor-port.sh)}" \
	  TO='$(TO)' \
	  scripts/ca-rotate.sh rotate

## innsegl-ca-rollback: put an archived Fulcio CA back, keeping the current one
##   in the archive. CONFIRM=rollback STAMP=<archive name>
innsegl-ca-rollback:
	@INNSEGL_STACK_PREFIX='$(STACK_PREFIX)' scripts/ca-rotate.sh rollback '$(STAMP)'

## install-hooks: refuse a commit that would track a local-only spec
# The gate in CI is the enforcement; this is the fast answer. Hooks do not
# travel with a clone, so this has to be run per checkout — and a subagent on a
# checkout that never ran it is exactly why the gate exists as well.
#
# IT DOES NOT COPY INTO .git/hooks, and that is the whole lesson. This
# repository sets core.hooksPath to scripts/hooks, so .git/hooks is never
# consulted — a hook installed there is silently dead and nothing reports it.
# Measured on 2026-09-17 by installing one, watching a commit that should have
# been refused succeed, and finding the threat model committed onto main.
#
# `git rev-parse --git-path hooks/pre-commit` answers where git will ACTUALLY
# look, honouring core.hooksPath, so the check at the end is the real question
# rather than a restatement of what was just done.
install-hooks:
	@dest="$$(git config core.hooksPath 2>/dev/null)"; \
	 if [ -n "$$dest" ]; then \
	   echo "core.hooksPath is $$dest; the hook is tracked there already"; \
	 else \
	   git config core.hooksPath scripts/hooks; \
	   echo "core.hooksPath set to scripts/hooks, where the tracked hooks live"; \
	 fi
	@chmod +x scripts/hooks/pre-commit 2>/dev/null || true
	@# THE ONLY QUESTION WORTH ASKING is where git will actually look, which
	@# --git-path answers by honouring core.hooksPath. Reporting "installed"
	@# because a file was copied is what put a hook in .git/hooks and let the
	@# threat model through.
	@live="$$(git rev-parse --git-path hooks/pre-commit)"; \
	 if [ -x "$$live" ]; then \
	   echo "active: $$live"; \
	   echo "a commit tracking anything under docs/ except docs/adr/ is refused"; \
	 else \
	   echo "NOT ACTIVE: git looks at $$live and there is no executable hook there." >&2; \
	   echo "  core.hooksPath is an absolute path, so a linked worktree uses the" >&2; \
	   echo "  main checkout's directory — this hook becomes live once it is merged." >&2; \
	   echo "  The CI gate is the enforcement in any case; this is only the fast answer." >&2; \
	   exit 1; \
	 fi

## test-ids: every test id in the code has a row in doc 07
# LOCAL ONLY, and not a CI gate, because doc 07 is local only: `docs/*` is
# gitignored and never pushed, so a runner has no catalog to check against.
# #167 and #169 both record the reason it is wanted — "nothing in this
# repository enforces test-ID uniqueness, and three collisions have already been
# caught by hand this week."
test-ids:
	@scripts/test-ids.sh

## innsegl-verify: ask the two servers what this deployment's credentials can do
#
# doc 05 §1 requires a database role that appends and cannot delete. This does
# not read the GRANTs, it attempts the writes and classifies the refusals by
# SQLSTATE — see deploy/compose/innsegl/verify-role.sh for why a check that
# asked "did it fail?" would pass the database owner. It writes nothing: every
# probe runs in a transaction that is rolled back.
#
# The second half asks the object store the same kind of question about the
# sealer's credential (#228): it must be able to read the bucket's object-lock
# rule and must not be able to set it. Both run at provisioning time already;
# this is how an operator re-asks a stack that has been up for a year, because
# an identity file written once lives in somebody's deployment and one line
# changed in it later — a bucket-wide write grant in place of the prefix-scoped
# one — leaves no trace in this repository.
innsegl-verify:
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_COMPOSE) run --rm --entrypoint sh innsegl-db-init \
	  /innsegl/init/verify-role.sh
	INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  $(INNSEGL_COMPOSE) run --rm --entrypoint sh innsegl-object-init \
	  /innsegl/init/verify-object-scope.sh

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
	  --network $(STACK_PREFIX)-sigstore-published \
	  --user 1000:1000 \
	  --volume $(STACK_PREFIX)-core_innsegl-workspace:/work:ro \
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
	  $(INNSEGL_COMPOSE) --profile demo --profile canary --profile separate down

## innsegl-purge: tear the innsegl stack down AND delete its data volumes
# Everything innsegl-down's comment says will happen, on purpose.
innsegl-purge:
	-INNSEGL_SPIRE_JWT_ISSUER='$(INNSEGL_SPIRE_JWT_ISSUER)' \
	  INNSEGL_SPIRE_PARENT_ID=unset \
	  $(INNSEGL_TRUST_ENV) $(GUARD) docker compose $(INNSEGL_FILES) \
	  --profile demo --profile canary --profile separate down -v

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
# THROUGH THE SERVICE'S OWN IMAGE, so this is the same command on both
# platforms and needs nothing installed on the machine. The script became a
# network client and wants a Postgres client wherever it runs; the service
# carries one, and the alternative — "install postgresql-client first" — is the
# host dependency this issue exists to remove.
#
# The host folder the copy lands in (RM-190, #310) is made here first, as the
# user running make: a bind-mount source that does not exist is created by the
# runtime, and on Linux that means owned by root and unwritable by the backup.
innsegl-backup:
	mkdir -p "$${INNSEGL_BACKUP_HOST_DIR:-$$HOME/innsegl-backups}"
	$(INNSEGL_COMPOSE) run --rm --entrypoint /innsegl/scripts/backup-ledger.sh \
	  innsegl-backup --out /backups

# THE SCHEDULE IS NOT HERE ANY MORE (RM-146, #237). It was a host scheduler —
# launchd on one platform, systemd on the other, two unit layouts, and a
# scheduler that has to exist at all; three CI failures in one day came from
# that split, every one of them in the harness rather than in the thing being
# tested. It also reached the ledger through the container runtime, so the
# thing taking backups held a socket that is root on the machine.
#
# `innsegl-backup` in deploy/compose/innsegl.yml is the schedule now: it starts
# and stops with the stack, holds no socket, and reports through its own
# healthcheck when a backup has not happened inside its window. The target
# above stays for the one-off run an operator wants to take by hand.
#
# It needs a Postgres client, because it stopped reaching into containers and
# became a network client. The service carries one; on a machine that does not,
# run it the way the service does:
#
#   docker compose -f deploy/compose/innsegl.yml run --rm \
#     --entrypoint /innsegl/scripts/backup-ledger.sh innsegl-backup --out /backups

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
# "checked" -- and the remedy is `make start` and run it again.
# ---------------------------------------------------------------------------

# The compose default, so the two targets below resolve to a real URL when
# nothing is exported. Without it $(INNSEGL_REKOR_PORT) is empty, the URL is
# `http://127.0.0.1:` and the gate returns 4 for a reason that has nothing to
# do with the commits -- honest, since 4 is inconclusive rather than green, but
# a poor thing to hand someone running this for the first time. Override it the
# same way the runbook does when 3000 is taken.
# 23000 and not rekor's own 3000. Host port 3000 is among the most contested on
# a developer's machine -- a Node dev server, Grafana and OWASP Juice Shop all
# take it by default -- and a collision does not degrade gracefully: compose
# fails to bind, the recreate leaves rekor in `Created`, and signing stops until
# someone reads the error. MEASURED 2026-09-10: an unrelated container holding
# 3000 broke `innsegl-up-here` exactly that way. The MCP moved off 8080 for the
# same reason and landed on 280xx; this is the same move. The port INSIDE the
# container is still 3000 -- only the host binding moved.
INNSEGL_REKOR_PORT ?= $(shell $(STACK_SHELL_ENV) scripts/rekor-port.sh)

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
