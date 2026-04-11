# caddy-compose Makefile
# Builds images locally, pushes to Docker Hub, deploys via Composer GitOps.
#
# Remote operations go through Composer's API (via SSH + docker exec + wget)
# so they work even when Caddy is down (bypasses the HTTPS proxy).
#
# All settings can be overridden via environment variables or a .env.mk file.
# Required env var: COMPOSER_API_KEY (Composer API key for authenticated requests)

# ── Load overrides from .env.mk if it exists ───────────────────────
-include .env.mk

# ── Image tags ──────────────────────────────────────────────────────
CADDY_IMAGE   ?= erfianugrah/caddy:3.94.0-2.11.2
WAFCTL_IMAGE ?= erfianugrah/wafctl:2.97.0

# ── Remote host ─────────────────────────────────────────────────────
# SSH host alias or user@host for the deployment target.
REMOTE ?= servarr

# ── Composer settings ───────────────────────────────────────────────
# Container name running Composer on the remote host.
# All compose commands go through Composer's bundled binary (Unraid has
# no docker compose plugin). Lifecycle ops (up/restart) use Composer's
# API which handles SOPS .env decryption automatically.
COMPOSER_CONTAINER ?= composer
COMPOSER_STACK     ?= caddy

# ── Remote paths ────────────────────────────────────────────────────
STACK_PATH    ?= /opt/stacks/$(COMPOSER_STACK)/compose.yaml
AUTHELIA_DEST ?= /mnt/user/data/authelia/config

# ── WAF data paths (on remote host) ────────────────────────────────
WAF_CONFIG_PATH    ?= /mnt/user/data/wafctl/waf-config.json
WAF_SETTINGS_PATH  ?= /mnt/user/data/caddy/waf/custom-waf-settings.conf

# ── Computed helpers ────────────────────────────────────────────────
# Compose commands via Composer's bundled binary (read-only ops: ps, logs, exec)
COMPOSE_CMD = ssh $(REMOTE) "docker exec $(COMPOSER_CONTAINER) docker compose -f $(STACK_PATH)"

# Docker exec on running containers
EXEC_CMD = ssh $(REMOTE) "docker exec"

# Composer API POST via SSH → docker exec → wget
# Bypasses Caddy proxy — works even when Caddy is down.
# Usage: $(call composer-api,stacks/caddy/sync)
define composer-api
KEY=$$COMPOSER_API_KEY && \
ssh $(REMOTE) "docker exec $(COMPOSER_CONTAINER) wget -qO- -T 120 \
	--header=\"Authorization: Bearer $$KEY\" \
	--header=\"X-Requested-With: XMLHttpRequest\" \
	--post-data=\"\" \
	\"http://localhost:8080/api/v1/$(1)\""
endef

.PHONY: help build build-caddy build-wafctl push push-caddy push-wafctl \
        deploy deploy-caddy deploy-wafctl deploy-all scp-authelia authelia-notification \
        sync pull restart restart-force restart-caddy restart-wafctl restart-authelia \
        test test-go test-frontend test-e2e check status logs logs-caddy logs-wafctl \
        health version caddy-reload caddy-quick-reload waf-deploy waf-config waf-events \
        config clean scan scan-caddy scan-wafctl sign sign-caddy sign-wafctl \
        sbom sbom-caddy sbom-wafctl verify

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

version: ## Print current image versions
	@echo "caddy:  $(CADDY_IMAGE)"
	@echo "wafctl: $(WAFCTL_IMAGE)"

config: ## Show current configuration
	@echo "REMOTE:              $(REMOTE)"
	@echo "CADDY_IMAGE:         $(CADDY_IMAGE)"
	@echo "WAFCTL_IMAGE:        $(WAFCTL_IMAGE)"
	@echo "COMPOSER_CONTAINER:  $(COMPOSER_CONTAINER)"
	@echo "COMPOSER_STACK:      $(COMPOSER_STACK)"
	@echo "STACK_PATH:          $(STACK_PATH)"

# ── Build ───────────────────────────────────────────────────────────
# Pass NO_CACHE=1 to force --no-cache (needed after plugin version bumps).
# Example: make build-caddy NO_CACHE=1
DOCKER_BUILD_FLAGS ?=
ifdef NO_CACHE
  DOCKER_BUILD_FLAGS += --no-cache
endif

build: ## Build both images in parallel
	$(MAKE) -j2 build-caddy build-wafctl

build-caddy: ## Build Caddy image (reverse proxy + policy engine)
	docker build $(DOCKER_BUILD_FLAGS) -t $(CADDY_IMAGE) .

WAFCTL_VERSION := $(lastword $(subst :, ,$(WAFCTL_IMAGE)))

build-wafctl: ## Build wafctl image
	docker build $(DOCKER_BUILD_FLAGS) -t $(WAFCTL_IMAGE) --build-arg VERSION=$(WAFCTL_VERSION) -f wafctl/Dockerfile .

# ── Push ────────────────────────────────────────────────────────────
push: push-caddy push-wafctl ## Push both images to Docker Hub

push-caddy: ## Push Caddy image
	docker push $(CADDY_IMAGE)

push-wafctl: ## Push wafctl image
	docker push $(WAFCTL_IMAGE)

# ── Test ────────────────────────────────────────────────────────────
test: ## Run all tests in parallel
	$(MAKE) -j3 test-go test-crs-converter test-frontend

test-go: ## Run wafctl Go tests
	cd wafctl && go test -count=1 -timeout 60s ./...

test-crs-converter: ## Run CRS converter tests
	cd tools/crs-converter && go test -count=1 -timeout 60s ./...

test-frontend: ## Run frontend tests
	cd waf-dashboard && npx vitest run

test-e2e: ## Run e2e smoke tests (requires Docker)
	docker build -t caddy-e2e:local .
	docker build -t wafctl-e2e:local --build-arg VERSION=e2e -f wafctl/Dockerfile .
	docker compose -f test/docker-compose.e2e.yml up -d --wait --timeout 120
	cd test/e2e && go test -v -count=1 -timeout 600s ./...; rc=$$?; \
	cd ../.. && docker compose -f test/docker-compose.e2e.yml down -v; \
	exit $$rc

test-e2e-load: ## Run e2e + DDoS load tests with k6 (requires Docker + k6 image)
	docker compose -f test/docker-compose.e2e.yml up -d --wait --timeout 120
	cd test/e2e && DDOS_LOAD=1 go test -v -count=1 -timeout 600s -run "TestDDoS" ./...; rc=$$?; \
	cd ../.. && docker compose -f test/docker-compose.e2e.yml down -v; \
	exit $$rc

test-playwright: ## Run Playwright browser tests (requires Docker stack running)
	docker compose -f test/docker-compose.e2e.yml up -d --wait --timeout 120
	cd test/playwright && npx playwright test; rc=$$?; \
	cd ../.. && docker compose -f test/docker-compose.e2e.yml down -v; \
	exit $$rc

test-crs-e2e: ## Run standalone CRS regression tests (requires Docker)
	docker build -t caddy-e2e:local .
	docker build -t wafctl-e2e:local --build-arg VERSION=e2e -f wafctl/Dockerfile .
	docker compose -f test/crs/docker-compose.crs.yml up -d --wait --timeout 120
	cd test/crs && go test -v -count=1 -timeout 600s ./...; rc=$$?; \
	cd ../.. && docker compose -f test/crs/docker-compose.crs.yml down -v; \
	exit $$rc

test-crs-e2e-update: ## Run CRS regression tests and update baseline (with events API cross-rule resolution)
	docker build -t caddy-e2e:local .
	docker build -t wafctl-e2e:local --build-arg VERSION=e2e -f wafctl/Dockerfile .
	docker compose -f test/crs/docker-compose.crs.yml up -d --wait --timeout 120
	cd test/crs && CRS_UPDATE_BASELINE=1 go test -v -count=1 -timeout 600s ./...; rc=$$?; \
	cd ../.. && docker compose -f test/crs/docker-compose.crs.yml down -v; \
	exit $$rc

check: test ## Run tests + type check + build (pre-push validation)
	cd waf-dashboard && npx tsc --noEmit
	cd waf-dashboard && npm run build

# ── CRS ─────────────────────────────────────────────────────────────
CRS_DIR ?= tools/coreruleset/rules

generate-rules: ## Regenerate default-rules.json + crs-metadata.json from CRS
	cd tools/crs-converter && go build -o /tmp/crs-converter .
	/tmp/crs-converter \
		-crs-dir $(CRS_DIR) \
		-crs-version "$$(cd tools/coreruleset && git describe --tags --always 2>/dev/null || echo unknown)" \
		-custom-rules waf/custom-rules.json \
		-output waf/default-rules.json \
		-metadata-output waf/crs-metadata.json

# ── Security: scan, sign, SBOM ──────────────────────────────────────
TRIVY_SEVERITY ?= CRITICAL,HIGH
SBOM_DIR       ?= .sbom

scan: scan-caddy scan-wafctl ## Scan both images for vulnerabilities

scan-caddy: ## Trivy scan Caddy image
	trivy image --severity $(TRIVY_SEVERITY) --exit-code 1 $(CADDY_IMAGE)

scan-wafctl: ## Trivy scan wafctl image
	trivy image --severity $(TRIVY_SEVERITY) --exit-code 1 $(WAFCTL_IMAGE)

sign: sign-caddy sign-wafctl ## Sign both images (keyless / Sigstore)

sign-caddy: ## Sign Caddy image with cosign (keyless, by digest)
	cosign sign $$(docker inspect --format='{{index .RepoDigests 0}}' $(CADDY_IMAGE))

sign-wafctl: ## Sign wafctl image with cosign (keyless, by digest)
	cosign sign $$(docker inspect --format='{{index .RepoDigests 0}}' $(WAFCTL_IMAGE))

COSIGN_IDENTITY ?= https://github.com/erfianugrah/caddy-compose/.github/workflows/build.yml@refs/heads/main
COSIGN_ISSUER   ?= https://token.actions.githubusercontent.com

verify: ## Verify signatures on both images
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(CADDY_IMAGE)) \
		--certificate-identity='$(COSIGN_IDENTITY)' \
		--certificate-oidc-issuer='$(COSIGN_ISSUER)'
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(WAFCTL_IMAGE)) \
		--certificate-identity='$(COSIGN_IDENTITY)' \
		--certificate-oidc-issuer='$(COSIGN_ISSUER)'

sbom: sbom-caddy sbom-wafctl ## Generate SBOMs for both images

sbom-caddy: ## Generate SBOM for Caddy image and attest to registry (by digest)
	@mkdir -p $(SBOM_DIR)
	syft $(CADDY_IMAGE) -o spdx-json=$(SBOM_DIR)/caddy.spdx.json -o cyclonedx-json=$(SBOM_DIR)/caddy.cdx.json
	cosign attest --yes --predicate $(SBOM_DIR)/caddy.spdx.json --type spdxjson $$(docker inspect --format='{{index .RepoDigests 0}}' $(CADDY_IMAGE))

sbom-wafctl: ## Generate SBOM for wafctl image and attest to registry (by digest)
	@mkdir -p $(SBOM_DIR)
	syft $(WAFCTL_IMAGE) -o spdx-json=$(SBOM_DIR)/wafctl.spdx.json -o cyclonedx-json=$(SBOM_DIR)/wafctl.cdx.json
	cosign attest --yes --predicate $(SBOM_DIR)/wafctl.spdx.json --type spdxjson $$(docker inspect --format='{{index .RepoDigests 0}}' $(WAFCTL_IMAGE))

# ── Remote operations (via Composer) ────────────────────────────────
# Lifecycle ops (sync/up/restart) use Composer API which handles SOPS
# decryption of .env automatically. Read-only ops (ps/logs/exec) use
# Composer's bundled docker compose directly.

sync: ## Sync stack git repo via Composer
	@$(call composer-api,stacks/$(COMPOSER_STACK)/sync)

pull: ## Pull images on remote
	$(COMPOSE_CMD) pull

restart: ## Redeploy stack via Composer (handles SOPS, force-recreate)
	@$(call composer-api,stacks/$(COMPOSER_STACK)/sync)
	@$(call composer-api,stacks/$(COMPOSER_STACK)/up)

restart-caddy: ## Recreate only Caddy (preserves Authelia sessions)
	$(COMPOSE_CMD) up -d --force-recreate caddy

restart-wafctl: ## Recreate only wafctl (preserves Authelia sessions)
	$(COMPOSE_CMD) up -d --force-recreate wafctl

restart-authelia: ## Recreate only Authelia (will invalidate sessions)
	$(COMPOSE_CMD) up -d --force-recreate authelia

restart-force: ## Force restart all containers (re-reads bind-mounted configs)
	$(COMPOSE_CMD) restart

down: ## Stop and remove all containers
	$(COMPOSE_CMD) down

status: ## Show container status on remote
	$(COMPOSE_CMD) ps

logs: ## Tail logs from all containers
	$(COMPOSE_CMD) logs --tail 30

logs-caddy: ## Tail Caddy logs
	$(COMPOSE_CMD) logs --tail 50 caddy

logs-wafctl: ## Tail wafctl logs
	$(COMPOSE_CMD) logs --tail 50 wafctl

health: ## Check wafctl API health on remote
	@$(EXEC_CMD) wafctl wget -qO- http://localhost:8080/api/health 2>/dev/null || echo "Health check failed"

# ── SCP (non-git-managed configs) ──────────────────────────────────
scp-authelia: ## SCP Authelia config + users database to remote
	scp authelia/configuration.yml $(REMOTE):$(AUTHELIA_DEST)/configuration.yml
	scp authelia/users_database.yml $(REMOTE):$(AUTHELIA_DEST)/users_database.yml

authelia-notification: ## Fetch and display Authelia 2FA notification.txt from remote
	@ssh $(REMOTE) "cat $(AUTHELIA_DEST)/notification.txt"

# ── Composite deploy targets ────────────────────────────────────────
# Caddyfile is now git-managed — Composer sync updates it automatically.
# No SCP needed. Push to main → webhook → Composer sync + redeploy.
deploy-caddy: build-caddy scan-caddy push-caddy sync restart ## Build, scan, push, sync, restart Caddy
	@echo "Caddy deployed."

deploy-wafctl: build-wafctl scan-wafctl push-wafctl sync restart ## Build, scan, push, sync, restart wafctl
	@echo "wafctl deployed."

deploy-all: build scan push sync restart ## Full deploy: build + scan + push + sync + restart
	@echo "Full deploy complete."

deploy: deploy-all ## Alias for deploy-all

deploy-noscan: build push sync restart ## Deploy without Trivy scan (use when upstream CVEs block scan)
	@echo "Deploy complete (scan skipped)."

# ── Release (deploy + sign + SBOM) ─────────────────────────────────
release-caddy: deploy-caddy sign-caddy sbom-caddy ## Deploy Caddy + sign + SBOM
	@echo "Caddy released (signed + SBOM attached)."

release-wafctl: deploy-wafctl sign-wafctl sbom-wafctl ## Deploy wafctl + sign + SBOM
	@echo "wafctl released (signed + SBOM attached)."

release: deploy-all sign sbom ## Full deploy + sign + SBOM
	@echo "Full release complete (signed + SBOM attached)."

# ── Caddy operations ────────────────────────────────────────────────
# Caddyfile is git-managed. Push changes, then reload.
caddy-reload: ## Sync Caddyfile from git, deploy WAF + CSP + security headers, reload Caddy
	@$(call composer-api,stacks/$(COMPOSER_STACK)/sync)
	$(EXEC_CMD) wafctl wget -qO- -T 120 http://localhost:8080/api/deploy --post-data=""
	$(EXEC_CMD) wafctl wget -qO- -T 120 http://localhost:8080/api/csp/deploy --post-data=""
	$(EXEC_CMD) wafctl wget -qO- -T 120 http://localhost:8080/api/security-headers/deploy --post-data=""

caddy-quick-reload: ## Sync Caddyfile from git and reload Caddy (no WAF/RL regeneration)
	@$(call composer-api,stacks/$(COMPOSER_STACK)/sync)
	$(EXEC_CMD) caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile

# ── WAF operations (via wafctl on remote) ──────────────────────────
waf-deploy: ## Trigger WAF config deploy (generate + reload Caddy)
	$(EXEC_CMD) wafctl wget -qO- -T 120 http://localhost:8080/api/config/deploy --post-data=""

waf-config: ## Show current WAF config from remote
	@echo "=== waf-config.json ==="
	@ssh $(REMOTE) "cat $(WAF_CONFIG_PATH)"
	@echo "\n=== custom-waf-settings.conf ==="
	@ssh $(REMOTE) "cat $(WAF_SETTINGS_PATH)"

waf-events: ## Show recent WAF events from remote (last 1h, limit 20)
	@$(EXEC_CMD) wafctl wget -qO- "http://localhost:8080/api/events?hours=1&limit=20" 2>/dev/null | python3 -m json.tool 2>/dev/null || \
		$(EXEC_CMD) wafctl wget -qO- "http://localhost:8080/api/events?hours=1&limit=20"

# ── Cleanup ─────────────────────────────────────────────────────────
clean: ## Remove local images and SBOM artifacts
	-docker rmi $(CADDY_IMAGE) 2>/dev/null
	-docker rmi $(WAFCTL_IMAGE) 2>/dev/null
	-rm -rf $(SBOM_DIR)
