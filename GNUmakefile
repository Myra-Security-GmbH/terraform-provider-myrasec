PKG_NAME = myrasec
GO = go
VERSION=$(shell git describe --tags --always)

default: build

build: useragent fmtcheck
	$(GO) install -ldflags="-X github.com/Myra-Security-GmbH/terraform-provider-myrasec/version.ProviderVersion=$(VERSION)"

fmt:
	@echo "==> Running gofmt..."
	gofmt -s -w ./$(PKG_NAME)

useragent:
	sed -i "s/terraform-provider-myrasec/terraform-provider-myrasec_$(VERSION)/g" ./myrasec/useragent.go

fmtcheck:
	@sh "$(CURDIR)/scripts/gofmtcheck.sh"

test: vendor
	$(GO) test -race $$($(GO) list ./...)

vendor:
	go mod vendor

cleandev:
	rm -rf terraform-provider-$(PKG_NAME)_*

dev: useragent cleandev
	$(GO) build -o terraform-provider-$(PKG_NAME)_$(VERSION)

.PHONY:test fmt fmtcheck
