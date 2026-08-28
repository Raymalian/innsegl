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

.PHONY: all build test lint cover smoke spire-up spire-verify spire-down clean

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

## smoke: boot the reference stack and verify a real signed commit (RM-054)
smoke:
	@echo 'make smoke: not implemented until RM-054.' >&2
	@echo 'It will boot the reference compose stack, run the demo agent, then verify' >&2
	@echo 'the resulting commit from a container with the ledger network detached.' >&2
	@exit 1

## clean: remove build and coverage artefacts
clean:
	rm -f $(BINARY) $(COVERPROFILE)
