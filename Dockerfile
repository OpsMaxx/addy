# addy ships as a static binary, so the runtime image holds the binary and
# nothing else.
#
# WHY FROM scratch AND NOT alpine: there is nothing for a shell to do in here.
# A shell in this image is a shell an attacker who reaches the process gets to
# use, and the only argument for keeping one -- debugging -- is answered by
# `docker run --rm -it ghcr.io/opsmaxx/addy version` and by the fact that every
# piece of state lives in a named volume you can mount somewhere else.
#
# The cost is real and worth stating: no `docker exec sh`, and a healthcheck
# must be the binary itself rather than a shell one-liner. That is why the
# compose healthcheck is `/addy selftest -quick -connect 127.0.0.1:443` in exec
# form.

FROM golang:1.26 AS build
WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module
# graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=0.0.0-dev
ARG BUILD_SHA=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -buildid= -X main.Version=${VERSION} -X main.BuildSha=${BUILD_SHA}" \
      -o /addy ./cmd/addy

FROM scratch
# CA roots, so the ACME client can verify the CA it is talking to. Without this
# every ACME order fails with an x509 error that reads like a clock problem.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /addy /addy

# addy binds 80 and 443, which on Linux needs either root or
# CAP_NET_BIND_SERVICE. The compose file runs it host-networked as root; a
# hardened deployment should drop to a uid and grant the capability instead.
#
# TURN is 3478/udp plus the relay range 61000-65535/udp (internal/relay), and
# nothing else: TURN over TLS is not implemented, and the EXPOSE for its port
# told every reader there was something listening there. The range is not EXPOSEd either
# -- the compose file is host-networked, so EXPOSE does nothing for it.
EXPOSE 80 443 3478/udp
VOLUME ["/var/lib/addy"]
ENTRYPOINT ["/addy"]
CMD ["serve"]
