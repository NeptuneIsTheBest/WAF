VERSION ?= 0.1.0
GO ?= go

.PHONY: all web build test race fuzz e2e schema check vuln scripts-check release clean
all: build
web:
	cd web && npm ci && npm run build
build:
	$(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/waf ./cmd/waf
schema:
	$(GO) run ./cmd/openapi
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
fuzz:
	$(GO) test ./internal/config -run '^$$' -fuzz FuzzDomainMatch -fuzztime 10s -parallel 2
	$(GO) test ./internal/policy -run '^$$' -fuzz FuzzCompileExpression -fuzztime 10s -parallel 2
e2e: build
	$(GO) build -o bin/waforigin ./cmd/waforigin
	cd web && npm run test:e2e
check:
	$(GO) vet ./...
	cd web && npx tsc -b
vuln:
	$(GO) tool govulncheck ./...
	cd web && npm audit --omit=dev
scripts-check:
	bash -n scripts/install.sh scripts/release.sh scripts/systemd-smoke.sh
	shellcheck scripts/install.sh scripts/release.sh scripts/systemd-smoke.sh
	python3 -m unittest discover -s scripts -p '*_test.py' -v
release:
	bash scripts/release.sh $(VERSION)
clean:
	rm -rf bin release
