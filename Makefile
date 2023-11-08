.ONESHELL:
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
# gnu date format iso-8601 is parsable with Go RFC3339
BUILDDATE := $(shell date --iso-8601=seconds)
VERSION := $(or ${VERSION},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

BINARY := gardener-vpn-gateway
LINKMODE := -extldflags '-static -s -w' \
	-X 'github.com/metal-stack/v.Version=$(VERSION)' \
	-X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
	-X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
	-X 'github.com/metal-stack/v.BuildDate=$(BUILDDATE)'

.PHONY: test
test:
	# go test -v -cover ./...

.PHONY: all
bin/$(BINARY): test
	GGO_ENABLED=1 \
	GO111MODULE=on \
		go build \
			-trimpath \
			-tags netgo \
			-o bin/$(BINARY) \
			-ldflags "$(LINKMODE)" -tags 'osusergo netgo static_build' . && strip bin/$(BINARY)
	strip bin/$(BINARY)

.PHONY: release
release: bin/$(BINARY)
	rm -rf rel
	mkdir -p rel/usr/local/bin
	cp bin/$(BINARY) rel/usr/local/bin
	cd rel \
	&& tar -cvzf $(BINARY).tgz usr/local/bin/$(BINARY) \
	&& mv $(BINARY).tgz .. \
	&& cd -

dockerimage:
	docker build -t ghcr.io/metal-stack/gardener-vpn-gateway .

.PHONY: all
all:: release;

.PHONY: push-to-gardener-local
push-to-gardener-local:
	$(MAKE)	bin/$(BINARY)
	docker build -f Dockerfile.dev -t ghcr.io/metal-stack/gardener-vpn-gateway:latest .
	kind --name gardener-local load docker-image ghcr.io/metal-stack/gardener-vpn-gateway:latest
