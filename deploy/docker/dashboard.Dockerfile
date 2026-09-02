# SPDX-License-Identifier: Apache-2.0
#
# The innsegl-dashboard image (RM-076, #109, doc 05 §1).
#
# doc 05 §1: "innsegl-dashboard | built | Read-only UI + BFF proof checks | No
# write credentials mounted — enforced by giving it a read-only DB role".
#
# THIS IMAGE IS THE UI HALF AND ONLY THE UI HALF, and that is stated here
# rather than left to be discovered from a blank page.
#
# The BFF is `internal/api` — server.go serves `GET /api/v1/runs` and
# `GET /api/v1/proof/{sha}`, and readonly.go provisions and then PROVES the
# read-only role doc 05 §1's note is about. It has no `cmd/` entry point: there
# is no `main` anywhere in this module that constructs an `api.Server`, so
# there is nothing to put in a container. Adding one is a `cmd/**` change and
# belongs to whoever owns that tree; until then this image serves the built
# React application and holds NO database credential at all, which satisfies
# "no write credentials mounted" in the only way currently available — by
# having none.
#
# The consequence an operator sees: the views render, and every one of them
# that reads the query API shows its own load-failure state. That is honest and
# it is visible, which is the whole argument of #109 — the alternative is a
# service that claims to be the dashboard row and quietly is not.
#
# BUILD (context is the REPOSITORY ROOT, not web/):
#   docker build -f deploy/docker/dashboard.Dockerfile -t innsegl-dashboard:dev .

# ---------------------------------------------------------------------------
# Builder.
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build

WORKDIR /src/web

# `npm ci` and not `npm install`: the lockfile is the pin, and an image built
# from a resolved-at-build-time dependency graph is an image nobody can
# reproduce.
COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
# `npm run build` is `tsc --noEmit && vite build` — the type check is part of
# the build on purpose (package.json), so an image cannot be produced from
# source the compiler rejects.
RUN npm run build

# ---------------------------------------------------------------------------
# Runtime. nginx-unprivileged: it listens on 8080 as a non-root user out of the
# box, which is what lets the compose service run with no capabilities at all.
# ---------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6

COPY deploy/docker/dashboard-nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/web/dist /usr/share/nginx/html

EXPOSE 8080
