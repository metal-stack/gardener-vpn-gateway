FROM golang:1.22 AS builder

WORKDIR /work

COPY .git Makefile go.* *.go /work/
COPY pkg/ /work/pkg/
RUN make bin/gardener-vpn-gateway

FROM debian:12-slim

COPY --from=builder /work/bin/gardener-vpn-gateway /

ENTRYPOINT ["/gardener-vpn-gateway"]
CMD ["/gardener-vpn-gateway"]
