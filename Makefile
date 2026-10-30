.PHONY: help all test coverage cover lint lint-ci vuln fmt fmt-check vet mod-check targets static fuzz soak golden bench tools replay build check clean coverage-check cross e2e interop

# Prefer module-local dependency resolution when a sibling go.work exists.
export GOWORK := off

help: ## Show targets and descriptions
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

APP_NAME   = mbtracectl
# The CLI is a nested module (ADR-0009): ./... of this module does not reach it.
CLI_DIR    = cmd/mbtracectl
GO_CLI     = go -C $(CLI_DIR)
BIN_DIR    = bin
BINARY     = $(BIN_DIR)/$(APP_NAME)

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
TAG        ?= $(shell git describe --tags --exact-match 2>/dev/null || echo "")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "-s -w -X 'main.version=$(VERSION)' -X 'main.tag=$(TAG)' -X 'main.commit=$(COMMIT)' -X 'main.buildDate=$(BUILD_DATE)'"

# CI formats with the Go version from go.mod; gofmt output can differ between releases.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

# Every target of REQUIREMENTS.md "Programs" builds with CGO_ENABLED=0 (L19).
TARGETS = linux/amd64 linux/arm64 linux/arm darwin/arm64 darwin/amd64 windows/amd64 windows/arm64

# Fuzz targets and the time each gets in `make fuzz`.
# Same minimum as coverage-min in ci.yml.
COVER_MIN := 90
FUZZ_TIME ?= 30s
FUZZ_TARGETS = ./internal/pcapio:FuzzPcapReader ./internal/pcapio:FuzzPcapngReader ./internal/link:FuzzLinkIPTCP \
	./mbtcp:FuzzFramer ./mbtcp:FuzzDecodeRequest ./mbtcp:FuzzDecodeResponse ./trace:FuzzPipeline

# The tools the replay test runs (TESTING.md section 5), pinned. modbusctl's
# v3 tags are not Go module versions (its module path has no /v3), so it is
# pinned by the pseudo-version of its v3.2.0 commit.
MBCAPCTL_VERSION  = v0.0.2
MODBUSCTL_VERSION = v0.0.0-20261015074520-c75d3676a93c

# Size of the generated stream in `make soak`, GiB.
SOAK_GIB ?= 5

all: check build ## Run checks and build bin/mbtracectl

coverage-check: coverage ## Fail when total coverage is below COVER_MIN
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if (t+0 < m+0) { printf "coverage %.1f%% < %s%%\n", t, m; exit 1 } else printf "coverage %.1f%% >= %s%%\n", t, m }'

cross: targets ## Alias of targets (GO-007 canonical name)

e2e: replay ## Alias of replay: mbtracectl output through the pinned mbcapctl and modbusctl (make tools)

interop: ## Compare the decoder with Wireshark's dissector (tshark on PATH; advisory, never a conformance claim)
	@command -v tshark >/dev/null || { echo "tshark is not installed"; exit 1; }
	@MBTRACE_ORACLE=1 go test -count=1 -run 'TestTsharkOracle|TestExtract' -v ./trace ./export/subtrace

check: fmt fmt-check mod-check lint lint-ci vet vuln test targets ## Format, lint, vet, vuln, test and cross-build

test: ## Run unit tests (race detector)
	@echo "Running go test -race ./..."
	@go test -count=1 -race ./...
	@cd $(CLI_DIR) && go test -count=1 -race ./...

coverage: ## Write coverage.out (atomic mode; -coverpkg=./... as in ci.yml)
	@echo "Running tests with coverage"
	@go test -count=1 -race -coverpkg=./... -coverprofile=coverage.out -covermode=atomic ./...

cover: coverage ## Open HTML coverage report
	@go tool cover -html=coverage.out

fuzz: ## Run every fuzz target for FUZZ_TIME
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t#*:}; \
		echo "Fuzzing $$name in $$pkg for $(FUZZ_TIME)"; \
		go test -run '^$$' -fuzz "^$$name$$" -fuzztime $(FUZZ_TIME) $$pkg || exit 1; \
	done

soak: ## Stream SOAK_GIB GiB of generated trace through Scan and check that memory stays flat
	@MBTRACE_SOAK=$(SOAK_GIB) go test -count=1 -run TestSoak -v -timeout 60m ./trace

golden: ## Regenerate docs/COVERAGE.md, the JSON Schemas, testdata/plant.pcapng and its output hashes
	@MBTRACE_UPDATE=1 go test -count=1 -run TestCoverageDoc ./mbtcp
	@cd $(CLI_DIR) && MBTRACE_UPDATE=1 go test -count=1 -run TestSchemasUpToDate .
	@MBTRACE_UPDATE=1 go test -count=1 -run TestFixture ./trace
	@cd $(CLI_DIR) && MBTRACE_UPDATE=1 go test -count=1 -run TestGoldenOutputs .

tools: ## Install the pinned mbcapctl and modbusctl into GOBIN
	@go install github.com/otfabric/go-modbus-capture/cmd/mbcapctl@$(MBCAPCTL_VERSION)
	@go install github.com/otfabric/modbusctl@$(MODBUSCTL_VERSION)

replay: ## Run the end-to-end replay test; fails when the pinned tools are missing
	@MBTRACE_REQUIRE_TOOLS=1 go test -count=1 -run 'TestReplayEndToEnd' -v ./export/mbcapexport

bench: ## Run benchmarks
	@go test -run '^$$' -bench . -benchmem ./...

lint: ## Run staticcheck
	@echo "Running staticcheck"
	@staticcheck ./...
	@cd $(CLI_DIR) && staticcheck ./...

lint-ci: ## Run golangci-lint (.golangci.yml)
	@echo "Running golangci-lint"
	@golangci-lint run ./...
	@cd $(CLI_DIR) && golangci-lint run ./...

fmt: ## gofmt all Go sources with the go.mod Go version
	@echo "Running gofmt (go$(GO_MOD_VERSION))"
	@$(GOFMT_CI) -w .

fmt-check: ## Fail if the go.mod-version gofmt or the local gofmt would change any file
	@ci="$$($(GOFMT_CI) -l .)"; loc="$$(gofmt -l .)"; \
	if [ -n "$$ci$$loc" ]; then echo "Not formatted:"; echo "$$ci $$loc"; exit 1; fi

mod-check: ## Fail on a replace directive or a local path in go.mod
	@if grep -nE '^[[:space:]]*replace|=>' go.mod; then echo "go.mod must not contain replace directives"; exit 1; fi

vet: ## go vet
	@go vet ./...
	@cd $(CLI_DIR) && go vet ./...

vuln: ## Run govulncheck
	@govulncheck ./...
	@cd $(CLI_DIR) && govulncheck ./...

targets: ## Cross-build every package for every target with CGO_ENABLED=0
	@for t in $(TARGETS); do \
		echo "Building $$t"; \
		GOOS=$${t%/*} GOARCH=$${t#*/} GOARM=7 CGO_ENABLED=0 go build ./... || exit 1; \
		(cd $(CLI_DIR) && GOOS=$${t%/*} GOARCH=$${t#*/} GOARM=7 CGO_ENABLED=0 go build -o "$(CURDIR)/$(BIN_DIR)/targets/$$t/" ./...) || exit 1; \
	done

static: ## Build mbtracectl for the Linux gateways and check that it is statically linked
	@mkdir -p $(BIN_DIR)
	@for a in amd64 arm64 arm; do \
		GOOS=linux GOARCH=$$a GOARM=7 CGO_ENABLED=0 $(GO_CLI) build -trimpath $(LDFLAGS) -o "$(CURDIR)/$(BIN_DIR)/$(APP_NAME)-linux-$$a" . || exit 1; \
		file $(BIN_DIR)/$(APP_NAME)-linux-$$a | grep -q 'statically linked' || { file $(BIN_DIR)/$(APP_NAME)-linux-$$a; exit 1; }; \
		echo "$(APP_NAME)-linux-$$a: static"; \
	done

build: ## Build $(BINARY) (static)
	@mkdir -p $(BIN_DIR)
	@CGO_ENABLED=0 $(GO_CLI) build $(LDFLAGS) -o "$(CURDIR)/$(BINARY)" .

clean: ## Remove bin/ and coverage.out
	@rm -rf $(BIN_DIR) coverage.out
