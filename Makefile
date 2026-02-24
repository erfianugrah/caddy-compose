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
CADDY_IMAGE   ?= erfianugrah/caddy:1.23.0-2.10.2
WAF_API_IMAGE ?= erfianugrah/waf-api:0.17.0

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
WAF_CONFIG_PATH    ?= /mnt/user/data/waf-api/waf-config.json
WAF_SETTINGS_PATH  ?= /mnt/user/data/caddy/coraza/custom-waf-settings.conf

# ── Computed helpers ────────────────────────────────────────────────
ifeq ($(DEPLOY_MODE),dockge)
  COMPOSE_CMD = ssh $(REMOTE) "docker exec $(DOCKGE_CONTAINER) docker compose -f $(STACK_PATH)"
  EXEC_CMD    = ssh $(REMOTE) "docker exec $(DOCKGE_CONTAINER) docker exec"
else
  COMPOSE_CMD = ssh $(REMOTE) "docker compose -f $(STACK_PATH)"
  EXEC_CMD    = ssh $(REMOTE) "docker exec"
endif

.PHONY: help build build-caddy build-waf-api push push-caddy push-waf-api \
        deploy deploy-caddy deploy-waf-api deploy-all scp scp-authelia authelia-notification pull restart restart-force \
        test test-go test-frontend status logs caddy-reload waf-deploy waf-config config

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

config: ## Show current configuration
	@echo "REMOTE:           $(REMOTE)"
	@echo "DEPLOY_MODE:      $(DEPLOY_MODE)"
	@echo "CADDY_IMAGE:      $(CADDY_IMAGE)"
	@echo "WAF_API_IMAGE:    $(WAF_API_IMAGE)"
	@echo "STACK_PATH:       $(STACK_PATH)"
	@echo "CADDYFILE_DEST:   $(CADDYFILE_DEST)"
	@echo "COMPOSE_DEST:     $(COMPOSE_DEST)"
ifeq ($(DEPLOY_MODE),dockge)
	@echo "DOCKGE_CONTAINER: $(DOCKGE_CONTAINER)"
endif

# ── Build ───────────────────────────────────────────────────────────
build: build-caddy build-waf-api ## Build both images

build-caddy: ## Build Caddy image (includes waf-dashboard)
	docker build -t $(CADDY_IMAGE) .

build-waf-api: ## Build waf-api image
	docker build -t $(WAF_API_IMAGE) -f waf-api/Dockerfile ./waf-api

# ── Push ────────────────────────────────────────────────────────────
push: push-caddy push-waf-api ## Push both images to Docker Hub

push-caddy: ## Push Caddy image
	docker push $(CADDY_IMAGE)

push-waf-api: ## Push waf-api image
	docker push $(WAF_API_IMAGE)

# ── Test ────────────────────────────────────────────────────────────
test: test-go test-frontend ## Run all tests

test-go: ## Run Go tests
	cd waf-api && go test -count=1 -timeout 60s ./...

test-frontend: ## Run frontend tests
	cd waf-dashboard && npx vitest run

# ── SCP / Deploy ────────────────────────────────────────────────────
scp: ## SCP Caddyfile + compose.yaml to remote
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

# ── Composite deploy targets ────────────────────────────────────────
deploy-caddy: build-caddy push-caddy scp pull restart ## Build, push, SCP, restart Caddy
	@echo "Caddy deployed."

deploy-waf-api: build-waf-api push-waf-api pull ## Build, push, restart waf-api
	$(COMPOSE_CMD) up -d waf-api
	@echo "waf-api deployed."

deploy-all: build push scp pull restart ## Full deploy: build + push + SCP + restart all
	@echo "Full deploy complete."

deploy: deploy-all ## Alias for deploy-all

# ── Caddy operations ────────────────────────────────────────────────
caddy-reload: ## SCP Caddyfile, sync rate limit zones, reload Caddy
	scp Caddyfile $(REMOTE):$(CADDYFILE_DEST)
	$(EXEC_CMD) waf-api wget -qO- http://localhost:8080/api/rate-limits/deploy --post-data=""

# ── WAF operations (via waf-api on remote) ──────────────────────────
waf-deploy: ## Trigger WAF config deploy (generate + reload Caddy)
	$(EXEC_CMD) waf-api wget -qO- http://localhost:8080/api/config/deploy --post-data=""

waf-config: ## Show current WAF config from remote
	@echo "=== waf-config.json ==="
	@ssh $(REMOTE) "cat $(WAF_CONFIG_PATH)"
	@echo "\n=== custom-waf-settings.conf ==="
	@ssh $(REMOTE) "cat $(WAF_SETTINGS_PATH)"
