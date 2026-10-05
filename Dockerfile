# SPDX-License-Identifier: Apache-2.0
#
# The innsegl image (RM-076, #109).
#
# ONE IMAGE, FIVE ROWS. doc 05 §1 gives `innsegl-mcp`, `innsegl-reconciler` and
# `innsegl-sealer` the same "built (same binary, subcommand)" note, and doc 05
# §3.1 adds the rule that decides the rest: "the verification BFF is the same
# Go binary as the CLI, never a second implementation at the edge (threat model
# §5.4 — divergent verifiers are a divergence in what 'verified' means)". So
# there is one image here and the compose services differ only by `command:`.
#
# Until #109 no Dockerfile existed anywhere in the repository. The consequence
# was not only that the reference deployment had no components in it: the
# release workflow (#64) publishes BINARIES ONLY because there was no image to
# sign, and every suite that needed a running `innsegl serve` bind-mounted a
# host-built binary into `alpine/git` with plain `docker run`.
#
# WHY THE RUNTIME IS NOT DISTROLESS, which is the obvious thing to reach for:
# `sign_commit` execs `git`, and it execs `gitsign` as git's `gpg.x509.program`
# (internal/signing). A scratch or distroless image would carry neither, and
# the MCP would fail every SIG-001 call at the point of signing. So the runtime
# is Alpine with git, and the trade — a shell in the image — is stated rather
# than discovered.
#
# WHY gitsign IS FETCHED HERE RATHER THAN VENDORED: it is deliberately not a
# go.mod dependency. Importing it would drag cosign and sigstore-go into a
# fourteen-entry module for a binary this project only ever execs, so it is
# pinned by version and built in the builder stage — the same pin and the same
# reasoning as test/smoke's.
#
# BUILD:
#   docker build -t innsegl:dev .
#   docker build -t innsegl:dev --build-arg VERSION=$(git describe --tags --always --dirty) \
#                --build-arg COMMIT=$(git rev-parse HEAD) \
#                --build-arg DATE=$(git log -1 --format=%cI) .
#
# deploy/compose/innsegl.yml passes those three, so a container started from
# the compose stack answers `innsegl version` with the commit it was built from.

# ---------------------------------------------------------------------------
# Builder. Pinned by tag AND digest, the same discipline spire.yml and
# sigstore.yml apply to every image they name: a tag is mutable at the
# registry, the digest is what docker verifies.
#
# --platform=$BUILDPLATFORM keeps the toolchain native and cross-compiles to
# TARGETARCH, which is what makes an arm64 laptop able to build the amd64 image
# without emulating a compiler.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:26402d86be3d72e6a9410afa0108f03529f51f0c1b5eb7f503d0bc44cc7857ac AS build

ARG TARGETOS
ARG TARGETARCH

# gitsign, pinned. The same version test/smoke asserts and CI installs.
ARG GITSIGN_VERSION=v0.17.1

WORKDIR /src

# Modules first, so a source-only change does not re-download the module graph.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# gitsign depends only on its pinned version, so it is built before the
# sources are copied: a code change no longer downloads and compiles it again.
#
# No GOBIN: `go install` refuses to cross-compile into one, so a build for
# another platform stopped here (measured 2026-10-04, arm64 building
# linux/amd64). It lands in GOPATH/bin/<os>_<arch> when cross-compiling and in
# GOPATH/bin when not; whichever it is, it is copied to /out.
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go install github.com/sigstore/gitsign@${GITSIGN_VERSION} \
 && gobin="$(go env GOPATH)/bin" && mkdir -p /out \
 && if [ -f "$gobin/${TARGETOS}_${TARGETARCH}/gitsign" ]; then cp "$gobin/${TARGETOS}_${TARGETARCH}/gitsign" /out/gitsign; \
    else cp "$gobin/gitsign" /out/gitsign; fi \
 && ls /out/gitsign

# The Go sources and nothing else: a change to the dashboard, the docs or
# the deployment files must not rebuild this image and restart every service
# that runs it. The Makefile's GO_IMAGE_INPUTS is the same list. (The UI is
# built in its own stage, ui-build, from web/ alone.)
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

# The version stamp. Defaulted rather than required so a bare `docker build .`
# still produces a working image; the compose stack and the release workflow
# pass the real values.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# CGO off: the binary has to run in a container that shares nothing with this
# one. `-trimpath` so the build path is not baked into it, which is half of
# what makes two builds of the same commit comparable.
ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-X innsegl.dev/innsegl/internal/version.version=${VERSION} \
                -X innsegl.dev/innsegl/internal/version.commit=${COMMIT} \
                -X innsegl.dev/innsegl/internal/version.date=${DATE}" \
      -o /out/innsegl ./cmd/innsegl

# The CA bootstrapper (RM-147, #238). Built here and shipped in its own target
# below, never in the runtime image: it is the program that decides what the
# CA's certificate says, and it has no business in the binary that holds SPIRE
# admin. Same argument innsegl.yml makes for generating the pseudonymisation
# secret in a container of its own.
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w" -o /out/ca-bootstrap ./cmd/ca-bootstrap


# ---------------------------------------------------------------------------
# Runtime.
#
# NAMED, and that is not decoration. An unnamed stage cannot be named by
# `target:`, so every service that builds this file without one gets whatever
# stage happens to be LAST. This stage was unnamed and last, so it was also the
# default — until `ca-bootstrap` was added after it, which silently moved the
# default to a one-shot CA tool. Measured 2026-09-18: a rebuild of innsegl-mcp
# produced an image whose entrypoint was ca-bootstrap, and the container
# crash-looped asking for a secret store. Six services build through the shared
# anchor and every one of them was affected; nothing failed at build time,
# because building the wrong stage is a perfectly good build.
# ---------------------------------------------------------------------------
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS runtime

# git      sign_commit execs it (internal/signing).
# ca-certificates  a deployment pointed at public Fulcio/Rekor needs a trust
#                  store; the compose stack's own Sigstore is plain HTTP on an
#                  internal network and does not, but the image is the same one
#                  a production deployment runs.
RUN apk add --no-cache git ca-certificates

# The commit this image was built from, so `make update` can tell a running
# stack that is already current from one that needs a build.
ARG COMMIT=unknown
LABEL dev.innsegl.commit=${COMMIT}

# uid 1000, non-root, and NOT an accident. `deploy/compose/spire/register.sh`
# selects spire-oidc on `unix:uid:1000` and calls uid 0 "the textbook weak
# selector" — every container runs as root by default, so an entry that
# selected on it would select everything. The MCP's registration entry uses the
# same selector, so this uid is part of the attestation surface.
RUN addgroup -g 1000 innsegl \
 && adduser -D -u 1000 -G innsegl -h /home/innsegl innsegl

COPY --from=build /out/innsegl /usr/local/bin/innsegl
COPY --from=build /out/gitsign /usr/local/bin/gitsign

# The named volumes' mountpoints, owned by the image's user.
#
# MEASURED, and it is the reason this line exists rather than being obvious:
# Docker initialises an EMPTY named volume from the image's content AND
# OWNERSHIP at the mount path. If the directory does not exist in the image, the
# daemon creates the mountpoint root-owned, and every container that mounts it
# as uid 1000 — the MCP, the reconciler, the demo agent — gets "Permission
# denied" on the first mkdir. Creating them here is what makes
# `innsegl-workspace` writable by the three services doc 05 §1 shares it
# between.
RUN mkdir -p /work && chown 1000:1000 /work

# /mirror is the per-repository mirror hosted clients push to (ADR-0065),
# owned by the image's user for the same reason as /work above.
RUN mkdir -p /mirror && chown 1000:1000 /mirror && chmod 0700 /mirror

# /dashboard-tls is where this process writes the dashboard's certificate
# and key (RM-311, #493); innsegl-api mounts it read-only, as this user, and
# serves the dashboard's HTTPS with it (#475).
RUN mkdir -p /dashboard-tls && chown 1000:1000 /dashboard-tls && chmod 0700 /dashboard-tls

# /message-key is RM-237's own derived agent-message key (E19, #395-#397): a
# named volume mounted read-write into innsegl-mcp and read-only into
# innsegl-api, so the run page's query API can VERIFY a brief or a reply's
# own keyed digest without ever holding -identity-secret. 0700, not the
# 1000:1000-owned default other volumes above get: this one holds
# cryptographic key material, however narrow its own capability (check-only,
# never a run token or a pseudonym — see gateway.go's own
# writeMessageKeyFile), and the directory bit is the second half of that
# narrowing, enforced again at runtime by writeMessageKeyFile itself in case
# this image is ever run with the mountpoint pre-created some other way.
RUN mkdir -p /message-key && chown 1000:1000 /message-key && chmod 0700 /message-key

# git and gitsign both want a writable HOME, and gitsign writes its cache
# there, so HOME is a real directory this user owns rather than `/`.
#
# INNSEGL_GITSIGN is the path internal/signing execs as git's
# `gpg.x509.program`. Set in the image rather than in the compose file because
# it is a property of THIS image's layout, not of a deployment's choices.
ENV HOME=/home/innsegl \
    INNSEGL_GITSIGN=/usr/local/bin/gitsign

USER 1000:1000
WORKDIR /home/innsegl

# No default subcommand. The five rows this image serves differ only by
# `command:`, and a default would make one of them the silent case — an
# operator who mistyped `innsegl-reconciler` would get an MCP server.
ENTRYPOINT ["/usr/local/bin/innsegl"]
CMD ["help"]

# ---------------------------------------------------------------------------
# The dashboard's UI, built (#475).
#
# web/ and nothing else, so a Go change does not rebuild it and a UI change
# does not rebuild the Go stages. `npm ci` and not `npm install`: the
# lockfile is the pin. `npm run build` is `tsc --noEmit && vite build`, so an
# image cannot be produced from source the compiler rejects.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS ui-build

WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# innsegl-api's image: the runtime above plus the built UI (#475).
#
# `innsegl api` serves the dashboard from INNSEGL_API_UI_DIR, which the
# compose file sets to this path. NOT go:embed: an embedded UI would make
# every dashboard change a new innsegl binary, a new runtime image, and a
# restart of the core. As its own target, a UI change rebuilds and restarts
# innsegl-api alone; every other service keeps the runtime image.
# ---------------------------------------------------------------------------
FROM runtime AS api

COPY --from=ui-build /src/web/dist /usr/share/innsegl/ui

# The UI's commit, beside the Go commit this image inherits from the runtime
# stage: between them they name every input of this image, so a deployment
# host can check an image it did not build (ADR-0070). After the COPY, so a
# new value relabels the image without rebuilding anything.
ARG UI_COMMIT=unknown
LABEL dev.innsegl.ui-commit=${UI_COMMIT}

# ---------------------------------------------------------------------------
# The backup's runtime (RM-146, #237).
# ---------------------------------------------------------------------------
# A SEPARATE TARGET AND NOT THE DEFAULT ONE, because the backup is the only row
# that needs two clients nothing else here wants: a Postgres client to take and
# restore the dump, and an S3 client to fetch the sealed segments it is
# adjudicated against.
#
# WHAT THIS REPLACES IS THE POINT. The backup used to run on the HOST, from a
# scheduler, and reached both of those through the container runtime — ten
# `docker exec`, two `docker cp` and a `docker run`. A process holding the
# runtime socket is root on the machine, and that is not a trade a backup may
# make. Everything below is a NETWORK client: it holds no socket, and
# OPS-044 asserts the call is refused.
#
# BOTH CLIENTS COME FROM THE SAME PINNED BASE, so there is one digest to audit
# rather than three images to keep in step:
#
#   postgresql16-client  matches the server major the deployment runs. A client
#                        older than the server cannot read its dumps, and
#                        pg_dump refuses the mismatch rather than truncating.
#   aws-cli              the reference implementation of the protocol, which is
#                        the same argument innsegl-object-init's image makes:
#                        the store's own tool cannot outlive the store.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS backup

# bash, because scripts/backup-ledger.sh is a bash script and has been since it
# was written for the host. Converting 380 lines of working shell to POSIX to
# save a megabyte would be a change with real risk and no benefit; the shell it
# declares is the shell it gets.
RUN apk add --no-cache bash postgresql16-client aws-cli ca-certificates

RUN addgroup -g 1000 innsegl \
 && adduser -D -u 1000 -G innsegl -h /home/innsegl innsegl

# The dumps' mountpoint, owned by the image's user, for the reason the runtime
# stage creates /work: an empty named volume inherits the image's ownership at
# the mount path, and a missing directory is created root-owned.
RUN mkdir -p /backups && chown 1000:1000 /backups

ENV HOME=/home/innsegl
USER 1000:1000
WORKDIR /home/innsegl

# No default command, for the reason the runtime stage gives: the scripts are
# mounted, and a default would make a mistyped command the silent case.
ENTRYPOINT ["/bin/sh"]

# The last commit that touched this stage, which copies nothing from the build
# context: the Dockerfile is its only input (ADR-0070). Last, so a new value
# relabels the image and reruns no step above.
ARG COMMIT=unknown
LABEL dev.innsegl.commit=${COMMIT}

# ---------------------------------------------------------------------------
# The CA bootstrapper's runtime (RM-147, #238) — rung 3.
# ---------------------------------------------------------------------------
# One static binary and a trust store, because all it does is speak HTTPS to a
# secret store and write a certificate. It runs once per bring-up of the
# key-custody profile and exits.
#
# WHAT IT DELIBERATELY DOES NOT CONTAIN: any way to read a private key. The CA
# key is created inside the store and never leaves it; this program holds a URL,
# a token and a key name, asks for signatures over digests, and mints a
# self-signed root from the answers. Reading this container yields the token —
# which is revocable and auditable — and never the key.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS ca-bootstrap

RUN apk add --no-cache ca-certificates

RUN addgroup -g 1000 innsegl \
 && adduser -D -u 1000 -G innsegl -h /home/innsegl innsegl

COPY --from=build /out/ca-bootstrap /usr/local/bin/ca-bootstrap

USER 1000:1000
WORKDIR /home/innsegl
ENTRYPOINT ["/usr/local/bin/ca-bootstrap"]
