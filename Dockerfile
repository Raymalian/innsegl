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
RUN go mod download

COPY . .

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
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-X innsegl.dev/innsegl/internal/version.version=${VERSION} \
                -X innsegl.dev/innsegl/internal/version.commit=${COMMIT} \
                -X innsegl.dev/innsegl/internal/version.date=${DATE}" \
      -o /out/innsegl ./cmd/innsegl

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOBIN=/out \
      go install github.com/sigstore/gitsign@${GITSIGN_VERSION} \
 && ls /out/gitsign

# ---------------------------------------------------------------------------
# Runtime.
# ---------------------------------------------------------------------------
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

# git      sign_commit execs it (internal/signing).
# ca-certificates  a deployment pointed at public Fulcio/Rekor needs a trust
#                  store; the compose stack's own Sigstore is plain HTTP on an
#                  internal network and does not, but the image is the same one
#                  a production deployment runs.
RUN apk add --no-cache git ca-certificates

# uid 1000, non-root, and NOT an accident. `deploy/compose/spire/register.sh`
# selects spire-oidc on `unix:uid:1000` and calls uid 0 "the textbook weak
# selector" — every container runs as root by default, so an entry that
# selected on it would select everything. The MCP's registration entry uses the
# same selector, so this uid is part of the attestation surface.
RUN addgroup -g 1000 innsegl \
 && adduser -D -u 1000 -G innsegl -h /home/innsegl innsegl

COPY --from=build /out/innsegl /usr/local/bin/innsegl
COPY --from=build /out/gitsign /usr/local/bin/gitsign

# The workspace root, owned by the image's user.
#
# MEASURED, and it is the reason this line exists rather than being obvious:
# Docker initialises an EMPTY named volume from the image's content AND
# OWNERSHIP at the mount path. If /work does not exist in the image, the daemon
# creates the mountpoint root-owned, and every container that mounts it as uid
# 1000 — the MCP, the reconciler, the demo agent — gets "Permission denied" on
# the first mkdir. Creating it here is what makes `innsegl-workspace` writable
# by the three services doc 05 §1 shares it between.
RUN mkdir -p /work && chown 1000:1000 /work

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
