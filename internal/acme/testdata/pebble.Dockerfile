# Pebble, the ACME test server, built from the upstream commit that fixes a
# deadlock in its order endpoint (upstream pull request 555). Every released
# image up to and including 2.10.1 takes the order's read lock twice in one
# request; when finalization's write lock queues in between, that request and
# every later one for the order hang for good. ACME clients poll the order
# while it is being finalized, so on a busy machine an order is lost now and
# then: "context deadline exceeded ... awaiting headers". Go back to a
# released image once one carries the fix.
FROM golang:1.27-alpine@sha256:26402d86be3d72e6a9410afa0108f03529f51f0c1b5eb7f503d0bc44cc7857ac AS build
ADD https://github.com/letsencrypt/pebble.git#755eb89b230af46382483a639837c8e6a508c39c /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -o /out/pebble ./cmd/pebble

# The released image's layout: the server at /app, its test files at /test.
FROM scratch
COPY --from=build /out/pebble /app
COPY --from=build /src/test /test
ENTRYPOINT ["/app"]
