# caddy-compose Makefile
# Builds images locally, pushes to Docker Hub, deploys to servarr via dockge.

# ── Image tags ──────────────────────────────────────────────────────
CADDY_IMAGE   := erfianugrah/caddy:1.15.0-2.10.2
WAF_API_IMAGE := erfianugrah/waf-api:0.10.0

# ── Remote paths ────────────────────────────────────────────────────
REMOTE          := servarr
DOCKGE_STACK    := /opt/stacks/caddy/compose.yaml
CADDYFILE_DEST  := /mnt/user/data/caddy/Caddyfile
COMPOSE_DEST    := /mnt/user/data/dockge/stacks/caddy/compose.yaml

# ── Dockge helper ───────────────────────────────────────────────────
# All docker compose commands must run inside the dockge container on servarr.
DOCKGE := ssh $(REMOTE) "docker exec dockge docker compose -f $(DOCKGE_STACK)"

.PHONY: help build build-caddy build-waf-api push push-caddy push-waf-api \
        deploy deploy-caddy deploy-waf-api deploy-all scp pull restart \
        test test-go test-frontend status logs waf-deploy waf-config

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

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
scp: ## SCP Caddyfile + compose.yaml to servarr
	scp Caddyfile $(REMOTE):$(CADDYFILE_DEST)
	scp compose.yaml $(REMOTE):$(COMPOSE_DEST)

pull: ## Pull images on servarr
	$(DOCKGE) pull

restart: ## Restart stack on servarr (pull + up)
	$(DOCKGE) up -d

status: ## Show container status on servarr
	$(DOCKGE) ps

logs: ## Tail logs from all containers
	$(DOCKGE) logs --tail 30

# ── Composite deploy targets ────────────────────────────────────────
deploy-caddy: build-caddy push-caddy scp pull restart ## Build, push, SCP, restart Caddy
	@echo "Caddy deployed."

deploy-waf-api: build-waf-api push-waf-api pull ## Build, push, restart waf-api
	$(DOCKGE) up -d waf-api
	@echo "waf-api deployed."

deploy-all: build push scp pull restart ## Full deploy: build + push + SCP + restart all
	@echo "Full deploy complete."

deploy: deploy-all ## Alias for deploy-all

# ── WAF operations (via waf-api on servarr) ─────────────────────────
waf-deploy: ## Trigger WAF config deploy (generate + reload Caddy)
	ssh $(REMOTE) 'docker exec dockge docker exec waf-api wget -qO- http://localhost:8080/api/config/deploy --post-data=""'

waf-config: ## Show current WAF config from servarr
	@echo "=== waf-config.json ==="
	@ssh $(REMOTE) "cat /mnt/user/data/waf-api/waf-config.json"
	@echo "\n=== custom-waf-settings.conf ==="
	@ssh $(REMOTE) "cat /mnt/user/data/caddy/coraza/custom-waf-settings.conf"
