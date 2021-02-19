PKG_NAME = myrasec
GO = go
VERSION=$(shell git describe --tags --always)

default: build

build: fmtcheck
	$(GO) install -ldflags="-X github.com/Myra-Security-GmbH/terraform-provider-myrasec/version.ProviderVersion=$(VERSION)"

fmt:
	@echo "==> Running gofmt..."
	gofmt -s -w ./$(PKG_NAME)

fmtcheck:
	@sh "$(CURDIR)/scripts/gofmtcheck.sh"

test: vendor
	$(GO) test -race $$($(GO) list ./...)

cleandev:
	rm -rf terraform-provider-$(PKG_NAME)_*

dev: cleandev
	$(GO) build -o terraform-provider-$(PKG_NAME)_$(VERSION)

.PHONY:test fmt fmtcheck
