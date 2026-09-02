# SPDX-License-Identifier: Apache-2.0
#
# doc 05 §1's `demo-agent` (RM-076, #109).
#
# A separate image from the innsegl one, and deliberately so. The demo agent is
# an MCP CLIENT: it needs curl, jq and git and it needs no part of this
# project's own code. Baking curl and jq into the innsegl image so that one
# image could serve both would put two tools an MCP server never uses into the
# container that holds the SPIRE admin credential, which is the wrong trade in
# the wrong direction.
#
# It also keeps the demonstration honest. deploy/compose/innsegl/demo-agent.sh
# explains why the client is a shell script rather than Go: a client sharing
# nothing with the server but the protocol is the thing worth showing.
#
# BUILD (context is the REPOSITORY ROOT):
#   docker build -f deploy/docker/demo-agent.Dockerfile -t innsegl-demo-agent:dev .

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache git curl jq

# uid 1000, matching the innsegl image. The demo agent stages a commit into the
# workspace volume that the MCP then signs in; two different uids on one shared
# working tree is git's "dubious ownership", and the signer builds its child
# environment as a whitelist, so there is no safe.directory to inject.
RUN addgroup -g 1000 innsegl \
 && adduser -D -u 1000 -G innsegl -h /home/innsegl innsegl

COPY deploy/compose/innsegl/demo-agent.sh /usr/local/bin/demo-agent
RUN chmod 0555 /usr/local/bin/demo-agent

ENV HOME=/home/innsegl
USER 1000:1000
WORKDIR /home/innsegl

ENTRYPOINT ["/usr/local/bin/demo-agent"]
