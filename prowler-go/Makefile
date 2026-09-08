GO ?= go
PKGS := ./...

.PHONY: build test lint vet fmt codegen bench cover

build:
	$(GO) build $(PKGS)

test:
	$(GO) test -race $(PKGS)

vet:
	$(GO) vet $(PKGS)

fmt:
	gofmt -l -w .

lint: vet
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest $(PKGS)

codegen:
	$(GO) run ./internal/codegen -source ../prowler/providers -out pkg/provider

bench:
	$(GO) test -bench=. -benchmem -run=^$$ $(PKGS)

cover:
	$(GO) test -coverprofile=coverage.out $(PKGS)
	$(GO) tool cover -func=coverage.out | tail -1
