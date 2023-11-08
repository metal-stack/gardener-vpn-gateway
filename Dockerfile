FROM golang:1.21 AS builder

WORKDIR /work

COPY .git Makefile go.* *.go /work/
COPY pkg/ /work/pkg/
RUN make bin/audit-forwarder

FROM debian:bullseye-20231030-slim

COPY --from=builder /work/bin/audit-forwarder /

ENTRYPOINT ["/audit-forwarder"]
CMD ["/audit-forwarder"]
