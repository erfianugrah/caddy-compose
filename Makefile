# caddy-compose Makefile
# Builds images locally, pushes to Docker Hub, deploys to a remote host.
#
# All settings can be overridden via environment variables or a .env.mk file.
# Example:
#   echo 'REMOTE=myhost' > .env.mk
#   echo 'DEPLOY_MODE=compose' >> .env.mk
#   make deploy
#
# Or inline:
#   make deploy REMOTE=myhost DEPLOY_MODE=compose

# ── Load overrides from .env.mk if it exists ───────────────────────
-include .env.mk

# ── Image tags ──────────────────────────────────────────────────────
CADDY_IMAGE   ?= erfianugrah/caddy:2.4.1-2.11.1
WAFCTL_IMAGE ?= erfianugrah/wafctl:1.4.1

# ── Remote host ─────────────────────────────────────────────────────
# SSH host alias or user@host for the deployment target.
REMOTE ?= servarr

# ── Deploy mode ─────────────────────────────────────────────────────
# "dockge"  — runs docker compose inside a dockge container (default)
# "compose" — runs docker compose directly on the remote host
DEPLOY_MODE ?= dockge

# ── Remote paths ────────────────────────────────────────────────────
# Where the compose stack lives on the remote host.
# Dockge mode: path inside the dockge container (mapped from host).
# Compose mode: absolute path on the remote host.
STACK_PATH     ?= /opt/stacks/caddy/compose.yaml
CADDYFILE_DEST ?= /mnt/user/data/caddy/Caddyfile
COMPOSE_DEST   ?= /mnt/user/data/dockge/stacks/caddy/compose.yaml
AUTHELIA_DEST  ?= /mnt/user/data/authelia/config

# For dockge mode only — the container name running dockge.
DOCKGE_CONTAINER ?= dockge

# ── WAF data paths (on remote host) ────────────────────────────────
WAF_CONFIG_PATH    ?= /mnt/user/data/wafctl/waf-config.json
WAF_SETTINGS_PATH  ?= /mnt/user/data/caddy/coraza/custom-waf-settings.conf

# ── Computed helpers ────────────────────────────────────────────────
ifeq ($(DEPLOY_MODE),dockge)
  COMPOSE_CMD = ssh $(REMOTE) "docker exec $(DOCKGE_CONTAINER) docker compose -f $(STACK_PATH)"
  EXEC_CMD    = ssh $(REMOTE) "docker exec $(DOCKGE_CONTAINER) docker exec"
else
  COMPOSE_CMD = ssh $(REMOTE) "docker compose -f $(STACK_PATH)"
  EXEC_CMD    = ssh $(REMOTE) "docker exec"
endif

.PHONY: help build build-caddy build-wafctl push push-caddy push-wafctl \
        deploy deploy-caddy deploy-wafctl deploy-all scp scp-authelia authelia-notification pull restart restart-force \
        test test-go test-frontend check status logs logs-caddy logs-wafctl \
        health version waf-deploy waf-config waf-events caddy-reload config clean \
        scan scan-caddy scan-wafctl sign sign-caddy sign-wafctl sbom sbom-caddy sbom-wafctl verify

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

version: ## Print current image versions
	@echo "caddy:  $(CADDY_IMAGE)"
	@echo "wafctl: $(WAFCTL_IMAGE)"

config: ## Show current configuration
	@echo "REMOTE:           $(REMOTE)"
	@echo "DEPLOY_MODE:      $(DEPLOY_MODE)"
	@echo "CADDY_IMAGE:      $(CADDY_IMAGE)"
	@echo "WAFCTL_IMAGE:    $(WAFCTL_IMAGE)"
	@echo "STACK_PATH:       $(STACK_PATH)"
	@echo "CADDYFILE_DEST:   $(CADDYFILE_DEST)"
	@echo "COMPOSE_DEST:     $(COMPOSE_DEST)"
ifeq ($(DEPLOY_MODE),dockge)
	@echo "DOCKGE_CONTAINER: $(DOCKGE_CONTAINER)"
endif

# ── Build ───────────────────────────────────────────────────────────
build: build-caddy build-wafctl ## Build both images

build-caddy: ## Build Caddy image (includes waf-dashboard)
	docker build -t $(CADDY_IMAGE) --build-arg WAFCTL_VERSION=$(WAFCTL_VERSION) .

WAFCTL_VERSION := $(lastword $(subst :, ,$(WAFCTL_IMAGE)))

build-wafctl: ## Build wafctl image
	docker build -t $(WAFCTL_IMAGE) --build-arg VERSION=$(WAFCTL_VERSION) -f wafctl/Dockerfile ./wafctl

# ── Push ────────────────────────────────────────────────────────────
push: push-caddy push-wafctl ## Push both images to Docker Hub

push-caddy: ## Push Caddy image
	docker push $(CADDY_IMAGE)

push-wafctl: ## Push wafctl image
	docker push $(WAFCTL_IMAGE)

# ── Test ────────────────────────────────────────────────────────────
test: test-go test-frontend ## Run all tests

test-go: ## Run Go tests
	cd wafctl && go test -count=1 -timeout 60s ./...

test-frontend: ## Run frontend tests
	cd waf-dashboard && npx vitest run

check: test ## Run tests + type check + build (pre-push validation)
	cd waf-dashboard && npx tsc --noEmit
	cd waf-dashboard && npm run build

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

verify: ## Verify signatures on both images
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(CADDY_IMAGE)) --certificate-identity-regexp='.*' --certificate-oidc-issuer-regexp='.*'
	cosign verify $$(docker inspect --format='{{index .RepoDigests 0}}' $(WAFCTL_IMAGE)) --certificate-identity-regexp='.*' --certificate-oidc-issuer-regexp='.*'

sbom: sbom-caddy sbom-wafctl ## Generate SBOMs for both images

sbom-caddy: ## Generate SBOM for Caddy image and attest to registry (by digest)
	@mkdir -p $(SBOM_DIR)
	syft $(CADDY_IMAGE) -o spdx-json=$(SBOM_DIR)/caddy.spdx.json -o cyclonedx-json=$(SBOM_DIR)/caddy.cdx.json
	cosign attest --yes --predicate $(SBOM_DIR)/caddy.spdx.json --type spdxjson $$(docker inspect --format='{{index .RepoDigests 0}}' $(CADDY_IMAGE))

sbom-wafctl: ## Generate SBOM for wafctl image and attest to registry (by digest)
	@mkdir -p $(SBOM_DIR)
	syft $(WAFCTL_IMAGE) -o spdx-json=$(SBOM_DIR)/wafctl.spdx.json -o cyclonedx-json=$(SBOM_DIR)/wafctl.cdx.json
	cosign attest --yes --predicate $(SBOM_DIR)/wafctl.spdx.json --type spdxjson $$(docker inspect --format='{{index .RepoDigests 0}}' $(WAFCTL_IMAGE))

# ── SCP / Deploy ────────────────────────────────────────────────────
scp: ## SCP Caddyfile + compose.yaml to remote
	@echo "Checking SSH connectivity to $(REMOTE)..."
	@ssh -o ConnectTimeout=30 $(REMOTE) true
	scp Caddyfile $(REMOTE):$(CADDYFILE_DEST)
	scp compose.yaml $(REMOTE):$(COMPOSE_DEST)

scp-authelia: ## SCP Authelia config + users database to remote
	scp authelia/configuration.yml $(REMOTE):$(AUTHELIA_DEST)/configuration.yml
	scp authelia/users_database.yml $(REMOTE):$(AUTHELIA_DEST)/users_database.yml

authelia-notification: ## Fetch and display Authelia 2FA notification.txt from remote
	@ssh $(REMOTE) "cat $(AUTHELIA_DEST)/notification.txt"

pull: ## Pull images on remote
	$(COMPOSE_CMD) pull

restart: ## Recreate containers on remote (picks up new images)
	$(COMPOSE_CMD) up -d

restart-force: ## Force restart all containers (re-reads bind-mounted configs)
	$(COMPOSE_CMD) restart

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

# ── Composite deploy targets ────────────────────────────────────────
deploy-caddy: build-caddy scan-caddy push-caddy scp pull restart ## Build, scan, push, SCP, restart Caddy
	@echo "Caddy deployed."

deploy-wafctl: build-wafctl scan-wafctl push-wafctl pull ## Build, scan, push, restart wafctl
	$(COMPOSE_CMD) up -d wafctl
	@echo "wafctl deployed."

deploy-all: build scan push scp pull restart ## Full deploy: build + scan + push + SCP + restart
	@echo "Full deploy complete."

deploy: deploy-all ## Alias for deploy-all

# ── Release (deploy + sign + SBOM) ─────────────────────────────────
release-caddy: deploy-caddy sign-caddy sbom-caddy ## Deploy Caddy + sign + SBOM
	@echo "Caddy released (signed + SBOM attached)."

release-wafctl: deploy-wafctl sign-wafctl sbom-wafctl ## Deploy wafctl + sign + SBOM
	@echo "wafctl released (signed + SBOM attached)."

release: deploy-all sign sbom ## Full deploy + sign + SBOM
	@echo "Full release complete (signed + SBOM attached)."

# ── Caddy operations ────────────────────────────────────────────────
caddy-reload: ## SCP Caddyfile, sync rate limit zones, reload Caddy
	scp Caddyfile $(REMOTE):$(CADDYFILE_DEST)
	$(EXEC_CMD) wafctl wget -qO- -T 120 http://localhost:8080/api/rate-limits/deploy --post-data=""

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
