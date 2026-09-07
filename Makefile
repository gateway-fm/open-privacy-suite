.PHONY: build build-prod test test-unit test-e2e test-privacy-bypass run dev-stack full-stack-dev run-binary clean clean-build \
	e2e e2e-all e2e-go e2e-playwright e2e-privacy e2e-chaos e2e-soak e2e-doctor e2e-debug e2e-down e2e-clean \
	demo-e2e demo-e2e-debug demo-e2e-down \
	db-migrate db-status db-new-migration install-tern seed \
	contracts-install contracts-build contracts-deploy \
	stop restart logs status \
	demo demo-record demo-process demo-all demo-setup demo-clean \
	quickstart quickstart-down quickstart-reset \
	setup-hooks ensure-hooks

# Auto-install hooks on first make usage (works in worktrees where .git is a file)
GIT_DIR := $(shell git rev-parse --git-dir)
HOOKS_MARKER := $(GIT_DIR)/.hooks-installed
$(HOOKS_MARKER):
	@./scripts/setup-hooks.sh
	@touch $(HOOKS_MARKER)

ensure-hooks: $(HOOKS_MARKER)

# Build identity injected into the binary via -ldflags (RD-1023).
# Overridable from the environment / CI; falls back to safe values when git
# is unavailable so a plain `make build` never fails.
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG := privacy-proxy/internal/version
LDFLAGS := -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(GIT_COMMIT) -X $(VERSION_PKG).BuildTime=$(BUILD_TIME)
# Export so docker-compose `args:` (and privacy-dev-up.sh) inherit the
# resolved build identity — otherwise compose builds report dev/none/unknown.
export VERSION GIT_COMMIT BUILD_TIME

# Build backend (dev, with mock auth)
build: ensure-hooks
	go build -tags mockauth -ldflags "$(LDFLAGS)" -o bin/privacy-proxy ./cmd/server

# Build production Docker image (no mock auth, no dev shortcuts).
# Build identity is passed in as build-args because the build context
# usually excludes .git, so `git describe` can't run inside the container.
build-prod: ensure-hooks
	docker build -f Dockerfile.backend --target prod \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t privacy-proxy:prod .

# Run full Docker stack (postgres, anvil, backend, frontend)
run: ensure-hooks
	docker-compose up --build -d
	@./scripts/print-urls.sh

# Start an isolated dev stack — auto-assigns offset ports so parallel stacks don't conflict.
# If REDIS_URL is set in .env or the environment, the built-in Redis is skipped
# and the backend connects to the external Redis instance.
dev-stack: ensure-hooks
	@if [ ! -f .env ] && [ "$$(basename "$$(pwd)")" != "privacy-proxy" ]; then \
		./scripts/stack-ports.sh auto > .env; \
		echo "Generated .env with offset ports (worktree detected)"; \
	fi
	@if grep -q '^REDIS_URL=' .env 2>/dev/null || [ -n "$${REDIS_URL}" ]; then \
		echo "External REDIS_URL detected — skipping built-in Redis"; \
		docker-compose up --build -d postgres anvil proxy-backend proxy-frontend; \
	else \
		docker-compose up --build -d; \
	fi
	@./scripts/print-urls.sh

# Bring up the full privacy-mode stack in dev mode:
# the Open Privacy Suite + chain-indexer + block-explorer (frontend + BFF).
# Requires sibling clones at ../block-explorer and ../chain-indexer
# (override with BLOCK_EXPLORER_PATH / CHAIN_INDEXER_PATH).
full-stack-dev:
	@./scripts/privacy-dev-up.sh

# One-command demo: self-contained stack (no sibling repos) + a seeded
# two-banks-and-a-regulator scenario with ready-to-use tokens. The place
# to start if you are evaluating the product — see ONBOARDING.md.
quickstart:
	@./scripts/quickstart.sh

quickstart-down:
	@./scripts/quickstart.sh --down

quickstart-reset:
	@./scripts/quickstart.sh --reset

# Stop all services
stop:
	docker-compose down

# Restart all services
restart:
	docker-compose down && docker-compose up --build -d
	@./scripts/print-urls.sh

# View logs
logs:
	docker-compose logs -f

# Show service status
status:
	docker-compose ps

# Run backend binary directly (without Docker)
run-binary: build
	./bin/privacy-proxy

# Run in dev mode (with hot reload)
dev: ensure-hooks
	go run ./cmd/server

# Run all tests (Go unit + Go e2e + Frontend)
test: ensure-hooks test-go frontend-test

# Run all Go tests (unit + e2e)
test-go: test-unit test-e2e

# Run Go unit tests only (with -p 1 to avoid database conflicts between packages).
# Tests spin their own ephemeral Postgres containers via testcontainers — they
# do NOT need the compose-managed dev postgres on host port 5432, so we don't
# pull in test-db-ready here. Forcing the dev postgres up made test-unit fail
# whenever another stack already held :5432 (RD-1010).
#
# Per-package timeout: 10m. The whole suite should finish in ~5min post-RD-1010
# (internal/server alone dropped from 898s → 13s thanks to shared testcontainer).
# A run that spills past 10m means something has regressed and should be fixed,
# not papered over with a larger budget.
test-unit:
	go test ./internal/... -v -p 1 -timeout 10m

# RD-1112: verify the async audit buffer is usable by the non-root runtime user
# in a fresh Docker named volume (the prod deploy scenario). Catches a broken
# Dockerfile pre-own step that a plain image build / Go tests would not.
.PHONY: verify-audit-buffer
verify-audit-buffer:
	@bash scripts/verify-audit-buffer-volume.sh

# RD-1166: regenerate the OpenAPI document from the swaggo handler annotations
# (swag v2 is pinned as a go.mod tool), refresh the docs-site copy, and rebuild
# the endpoint inventory from the live route table. All outputs are committed;
# CI regenerates and fails on drift. The route↔spec coverage gate lives in
# internal/server/openapi_coverage_test.go (runs with test-unit).
SWAG_EXCLUDES = ./site,./frontend,./e2e,./mcp,./contracts,./scripts,./monitoring,./demos,./docs
.PHONY: api-spec
api-spec:
	go tool swag init --v3.1 -q -g internal/server/openapi_general_info.go -d ./ \
		--exclude $(SWAG_EXCLUDES) -o internal/server/apispec --ot json,yaml \
		--parseInternal --parseDependencyLevel 1
	go run ./cmd/api-spec-postprocess
	cp internal/server/apispec/swagger.json site/public/openapi.json
	go run ./cmd/api-inventory

# RD-1166: regenerate only API_ENDPOINTS.md (method/path/auth inventory).
.PHONY: api-inventory
api-inventory:
	go run ./cmd/api-inventory

# Minimum coverage threshold (percentage) - start at 45%, increase over time
MIN_COVERAGE ?= 45

# Run unit tests with coverage
test-coverage:
	go test ./internal/... -v -p 1 -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run unit tests with coverage and enforce minimum threshold
test-coverage-check:
	go test ./internal/... -v -p 1 -coverprofile=coverage.out
	@COVERAGE=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	COVERAGE_INT=$${COVERAGE%.*}; \
	echo "Total coverage: $${COVERAGE}%"; \
	if [ "$$COVERAGE_INT" -lt "$(MIN_COVERAGE)" ]; then \
		echo "ERROR: Coverage $${COVERAGE}% is below minimum threshold of $(MIN_COVERAGE)%"; \
		exit 1; \
	fi; \
	echo "Coverage $${COVERAGE}% meets minimum threshold of $(MIN_COVERAGE)%"

# Check if test database is ready
test-db-ready:
	@echo "Checking PostgreSQL connection..."
	@docker-compose ps postgres | grep -q "Up" || (echo "PostgreSQL is not running. Starting it..." && docker-compose up -d postgres && sleep 2)
	@echo "PostgreSQL is ready"

# Run both Go E2E lanes (production tags and mockauth security coverage) through
# the isolated server harness.
test-e2e: ensure-hooks
	./scripts/e2e-harness.sh go

# Negative-network test for the privacy-mode deployment (RD-855 Phase 4b).
# Brings up docker-compose.privacy.yml (nine services) and verifies the
# trust boundary is closed: trust-zone services unreachable from the
# host, frontend routes correctly, /ws returns 404. The harness builds the
# current proxy plus pinned public ops-explorer and ops-indexer sources into
# project-local images while preserving the production Compose topology. It is
# build-tag gated so it doesn't run in default test runs or the pre-push hook.
test-privacy-bypass: ensure-hooks
	./scripts/e2e-harness.sh privacy

# Compose detection shared by the demo acceptance suite below. Prefer Compose
# v1 (docker-compose) when present so local dev is unchanged; fall back to the
# v2 plugin (docker compose) on CI runners that ship only v2. The isolated E2E
# harness (scripts/e2e-harness.sh) does its own compose handling.
COMPOSE := $(shell command -v docker-compose >/dev/null 2>&1 && echo docker-compose || echo docker compose)
BLOCK_EXPLORER_PATH ?= ../block-explorer
BLOCK_EXPLORER_GIT_COMMIT ?= $(shell git -C "$(BLOCK_EXPLORER_PATH)" rev-parse --short HEAD 2>/dev/null || echo unknown)
BLOCK_EXPLORER_VERSION ?= $(shell git -C "$(BLOCK_EXPLORER_PATH)" describe --tags --always --dirty 2>/dev/null || echo dev)
BLOCK_EXPLORER_BUILD_TIME ?= $(BUILD_TIME)
export BLOCK_EXPLORER_PATH BLOCK_EXPLORER_GIT_COMMIT BLOCK_EXPLORER_VERSION BLOCK_EXPLORER_BUILD_TIME
DEMO_E2E_COMPOSE = $(COMPOSE) --env-file e2e/demo.env -p privacy-proxy-demo-e2e -f docker-compose.privacy.dev.yml -f docker-compose.demo-e2e.yml
DEMO_E2E_SERVICES = privacy-postgres redis anvil indexer-postgres chain-indexer proxy-backend proxy-frontend block-explorer-postgres block-explorer-api block-explorer-frontend

# Server-safe E2E entry points. The harness assigns a unique Compose project,
# writes artifacts to a per-run directory, and only tears down resources owned
# by that run. See docs/e2e-server-harness.md for operator commands and knobs.
e2e: e2e-all

e2e-all: ensure-hooks
	./scripts/e2e-harness.sh all

e2e-go: ensure-hooks
	./scripts/e2e-harness.sh go

e2e-playwright: ensure-hooks
	./scripts/e2e-harness.sh playwright

e2e-privacy: ensure-hooks
	./scripts/e2e-harness.sh privacy

e2e-chaos: ensure-hooks
	./scripts/e2e-harness.sh chaos

e2e-soak: ensure-hooks
	./scripts/e2e-harness.sh soak

e2e-doctor: ensure-hooks
	./scripts/e2e-harness.sh doctor

# Compatibility target: run Playwright and retain this run's stack for
# inspection. Reuse E2E_RUN_ID and any explicit project/artifact overrides with
# e2e-down afterwards.
e2e-debug: ensure-hooks
	E2E_KEEP_STACK=1 ./scripts/e2e-harness.sh playwright

# Stop only projects marked as acquired by the selected run. Reuse its explicit
# E2E_RUN_ID plus any E2E_PROJECT, E2E_PRIVACY_PROJECT, and artifact override.
e2e-down:
	./scripts/e2e-harness.sh down

# Backwards-compatible alias; cleanup remains scoped to one harness run.
e2e-clean: e2e-down

# Cross-product demo acceptance suite: proxy + indexer + real block explorer.
# BLOCK_EXPLORER_PATH may point at a sibling worktree; CI checks out the pinned
# explorer revision next to this repository before invoking this target.
demo-e2e: ensure-hooks
	@status=0; \
	FOUNDRY_AUTO_DETECT_REMAPPINGS=false forge build --root contracts --skip script && \
	$(DEMO_E2E_COMPOSE) up -d --build $(DEMO_E2E_SERVICES) && \
	$(DEMO_E2E_COMPOSE) build playwright-demo && \
	$(DEMO_E2E_COMPOSE) run --rm --no-deps playwright-demo || status=$$?; \
	$(DEMO_E2E_COMPOSE) down -v --remove-orphans; \
	exit $$status

demo-e2e-debug: ensure-hooks
	FOUNDRY_AUTO_DETECT_REMAPPINGS=false forge build --root contracts --skip script
	$(DEMO_E2E_COMPOSE) up -d --build $(DEMO_E2E_SERVICES)
	$(DEMO_E2E_COMPOSE) build playwright-demo
	$(DEMO_E2E_COMPOSE) run --rm --no-deps playwright-demo npx playwright test --project=demo --debug
	@echo "Services still running. Run 'make demo-e2e-down' to stop them."

demo-e2e-down:
	$(DEMO_E2E_COMPOSE) down -v --remove-orphans

# Install frontend dependencies
frontend-install:
	cd frontend && npm install

# Run frontend dev server
frontend-dev:
	cd frontend && npm run dev

# Build frontend
frontend-build:
	cd frontend && npm run build

# Run frontend tests (auto-install if node_modules missing)
frontend-test:
	@test -x frontend/node_modules/.bin/vitest || (echo "Installing frontend dependencies..." && cd frontend && npm install)
	cd frontend && npm run test:run

# Run frontend tests with coverage
frontend-test-coverage:
	cd frontend && npm run test:coverage

# Alias for 'test'
test-all: test

# Clean only this checkout's default Compose project and its attached volumes.
# Never prune the shared Docker daemon from a repository target.
clean:
	docker-compose down -v --remove-orphans

# Clean build artifacts
clean-build:
	rm -rf bin/
	rm -rf frontend/dist/
	rm -rf frontend/node_modules/
	go clean

# Run database migrations (via Go - uses embedded migrations)
db-migrate:
	go run ./cmd/migrate

# Show migration status using tern CLI
db-status:
	@tern status -c tern.conf -m internal/db/migrations 2>/dev/null || \
		echo "Run 'make install-tern' to install tern CLI, or use 'make db-migrate' for Go-based migrations"

# Create a new migration file
# Usage: make db-new-migration name=add_user_table
db-new-migration:
	@if [ -z "$(name)" ]; then \
		echo "Usage: make db-new-migration name=migration_name"; \
		exit 1; \
	fi
	@next=$$(ls internal/db/migrations/*.sql 2>/dev/null | wc -l | tr -d ' '); \
	next=$$((next + 1)); \
	filename=$$(printf "%03d_%s.sql" $$next "$(name)"); \
	echo "-- $(name)" > "internal/db/migrations/$$filename"; \
	echo "" >> "internal/db/migrations/$$filename"; \
	echo "---- create above / drop below ----" >> "internal/db/migrations/$$filename"; \
	echo "" >> "internal/db/migrations/$$filename"; \
	echo "-- Optional: down migration" >> "internal/db/migrations/$$filename"; \
	echo "Created: internal/db/migrations/$$filename"

# Install tern CLI tool
install-tern:
	go install github.com/jackc/tern/v2@latest
	@echo "tern installed. Ensure \$$GOPATH/bin is in your PATH."

# Setup test databases
test-db-setup:
	./scripts/setup-test-db.sh

# Seed database with development data
seed:
	@echo "Seeding database with development data..."
	@docker-compose exec -T postgres psql -U postgres -d privacy_proxy < scripts/seed.sql
	@echo "Done!"

# ============================================================================
# Documentation Site
# ============================================================================

# Run docs site in development mode
site-dev:
	cd site && npm run dev

# Build docs site for production (static export)
site-build:
	cd site && npm run build

# Install docs site dependencies
site-install:
	cd site && npm install

# ============================================================================
# Contract Development (Foundry)
# ============================================================================

# Install Foundry dependencies (forge-std)
contracts-install:
	@echo "Installing Foundry dependencies..."
	cd contracts && forge install foundry-rs/forge-std --no-commit
	@echo "Done!"

# Build contracts
contracts-build:
	@echo "Building contracts..."
	cd contracts && forge build
	@echo "Done!"

# Deploy Counter contract to local Anvil
# Requires: Anvil running (use 'make run' to start all services)
# Uses Anvil's default account 0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
RPC_URL ?= http://localhost:$(or $(HOST_PORT_RPC),8545)

contracts-deploy:
	@echo "Deploying Counter contract to local Anvil..."
	@echo "Make sure Anvil is running (docker-compose up anvil)"
	cd contracts && forge script script/Deploy.s.sol:DeployCounter \
		--rpc-url $(RPC_URL) \
		--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
		--broadcast
	@echo ""
	@echo "Contract deployed! Add the address above to the admin UI contracts section."

# Deploy and show contract address (quieter output)
contracts-deploy-quiet:
	@cd contracts && forge script script/Deploy.s.sol:DeployCounter \
		--rpc-url $(RPC_URL) \
		--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
		--broadcast 2>&1 | grep -E "(Counter deployed to:|deployed)"

# ============================================================================
# Demo Video Generation
# ============================================================================

# Setup demo generation environment
demo-setup:
	@cd demos && make setup

# Generate complete demo video
# Usage: make demo name=auth-flow
demo:
	@cd demos && make demo name=$(name)

# Record video only (no processing)
# Usage: make demo-record name=auth-flow
demo-record:
	@cd demos && make demo-record name=$(name)

# Process existing recording
# Usage: make demo-process name=auth-flow
demo-process:
	@cd demos && make demo-process name=$(name)

# Generate all demo videos
demo-all:
	@cd demos && make demo-all

# List available demo configurations
demo-list:
	@cd demos && make demo-list

# Clean demo outputs
demo-clean:
	@cd demos && make clean

# ============================================================================
# Git Hooks
# ============================================================================

# Setup git hooks (run once after cloning)
setup-hooks:
	@./scripts/setup-hooks.sh

## proto-gen: Regenerate Go stubs from vendored chain-indexer .proto files.
##            We do NOT depend on chain-indexer's Go module — we carry our
##            own copy of the .proto contract and build stubs here. When
##            chain-indexer's proto surface changes, copy updated files
##            from chain-indexer/proto/chain_indexer/v1/*.proto and re-run.
.PHONY: proto-gen
proto-gen:
	@which buf > /dev/null || (echo "buf not installed: https://buf.build/docs/installation"; exit 1)
	buf generate

## proto-lint: Lint vendored .proto files.
.PHONY: proto-lint
proto-lint:
	@which buf > /dev/null || (echo "buf not installed"; exit 1)
	buf lint

## staging-create-test-accs: Generate the five deterministic staging test
##                           identities (alice/bob/carol/dave/eve) under
##                           tools/wallet-emulator-js/identities/. Idempotent
##                           + self-healing. Files are committed to git on
##                           purpose; see the script header for the security
##                           rationale.
.PHONY: staging-create-test-accs
staging-create-test-accs: require-wallet-emulator-submodule
	@cd tools/wallet-emulator-js && ./scripts/create-test-identities.sh

## wallet-emulator-circuits: Fetch the auth-v2 ZK circuit artifacts to
##                           PRIVADO_CIRCUITS_DIR (default: ~/.privado-circuits)
##                           if missing or checksum-drifted. Required by
##                           `wallet-emulator-js auth`. No-op when already
##                           present + verified. ~32 MB on first run.
PRIVADO_CIRCUITS_DIR ?= $(HOME)/.privado-circuits
# PROXY_URL must be passed explicitly by the caller — there is no committed
# default. It identifies the staging-proxy host the wallet-emulator
# authenticates against and is environment-specific.
#   make staging-test-accs PROXY_URL=https://your-staging-proxy.example.com
AUTHV2_WASM_SHA256 := 70affbca1ad1947d76784ca90f6c4a8fd143119685c9917a2a6fefc15b9ed7c1
AUTHV2_ZKEY_SHA256 := 6acb096a716f5f5b1e5505a7b7261c7eeb7f0a90597c5194fad7b14f91180ac1
AUTHV2_VKEY_SHA256 := 79cf543dd8300c0149454ddd200a0a1ac83eed1df4fb49bdceea4b5ebd2cec96
PRIVADO_BUNDLE_URL ?= https://circuits.privado.id/latest.zip

.PHONY: wallet-emulator-circuits
wallet-emulator-circuits:
	@./scripts/fetch-privado-circuits.sh "$(PRIVADO_CIRCUITS_DIR)" \
	  "$(PRIVADO_BUNDLE_URL)" \
	  "$(AUTHV2_WASM_SHA256)" "$(AUTHV2_ZKEY_SHA256)" "$(AUTHV2_VKEY_SHA256)"

## staging-circuits: Alias for `wallet-emulator-circuits`. Initialises just the
##                   auth-v2 ZK circuit artifacts (~32 MB fetch on first run,
##                   no-op when already present + SHA-256 verified).
.PHONY: staging-circuits
staging-circuits: wallet-emulator-circuits

## staging-auth-users: Authenticate every named test identity (alice/bob/carol/
##                     dave/eve) against the staging proxy and print a
##                     name → DID table. Use ./scripts/auth-as.sh <name> from
##                     tools/wallet-emulator-js/ to grab an actual JWT.
##                     Ensures circuits + identities exist via deps; safe to
##                     run on a fresh clone.
##                     Override the proxy with: make staging-auth-users PROXY_URL=https://...
# `require-PROXY_URL` runs before any auth-bearing target's deps so we
# fail fast — without it, a forgotten PROXY_URL still triggers the ~500
# MB circuit download before erroring out.
.PHONY: require-PROXY_URL
require-PROXY_URL:
	@if [ -z "$(PROXY_URL)" ]; then \
	  echo "error: PROXY_URL is required."; \
	  echo "       e.g. make staging-test-accs PROXY_URL=https://your-staging-proxy.example.com"; \
	  exit 2; \
	fi

# wallet-emulator-js lives in its own repo (gateway-fm/wallet-emulator-js)
# and is consumed here as a git submodule at tools/wallet-emulator-js/.
# A fresh clone without --recurse-submodules leaves the dir empty, so any
# target that shells into it fails with a confusing "no such file" — this
# gate gives the real fix instead.
.PHONY: require-wallet-emulator-submodule
require-wallet-emulator-submodule:
	@if [ ! -f tools/wallet-emulator-js/package.json ]; then \
	  echo "error: tools/wallet-emulator-js/ submodule is not initialized."; \
	  echo "       Run: git submodule update --init --recursive tools/wallet-emulator-js"; \
	  exit 2; \
	fi

.PHONY: staging-auth-users
staging-auth-users: require-PROXY_URL require-wallet-emulator-submodule staging-circuits staging-create-test-accs
	@echo "Authenticating against: $(PROXY_URL)"
	@echo
	@cd tools/wallet-emulator-js && PROXY_URL="$(PROXY_URL)" PRIVADO_CIRCUITS_DIR="$(PRIVADO_CIRCUITS_DIR)" ./scripts/auth-all.sh

## staging-cleanup: Wipe the fetched circuit artifacts and the persisted
##                  identity JSON files so the next `make staging-test-accs`
##                  exercises every step from scratch. Useful for clean-room
##                  testing; the identities regenerate deterministically so
##                  the DIDs after a wipe are bit-identical to before.
.PHONY: staging-cleanup
staging-cleanup:
	@echo "Removing $(PRIVADO_CIRCUITS_DIR)/authV2/ ..."
	@rm -rf "$(PRIVADO_CIRCUITS_DIR)/authV2"
	@echo "Removing tools/wallet-emulator-js/identities/ ..."
	@rm -rf tools/wallet-emulator-js/identities
	@echo "Done. Re-run 'make staging-test-accs' to exercise the full flow."

## staging-test-accs: Does it all. Init circuits if missing, create identities
##                    if missing, authenticate every test user against the
##                    staging proxy. Idempotent; the daily-driver target for
##                    "get the test users working from a fresh clone."
.PHONY: staging-test-accs
staging-test-accs: staging-auth-users
	@echo
	@echo "Refresh a single user's JWT (tokens are ~5 min):"
	@echo "  PROXY_URL=$(PROXY_URL) tools/wallet-emulator-js/scripts/auth-as.sh alice"
	@echo
	@echo "Capture for reuse:"
	@echo "  JWT=\$$(PROXY_URL=$(PROXY_URL) tools/wallet-emulator-js/scripts/auth-as.sh alice)"
