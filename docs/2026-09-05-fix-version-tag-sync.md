# Fix: image tag drift across the five version files

Status: OPEN (2026-09-05). Severity: medium (CI can overwrite a live tag).

## What is wrong

AGENTS.md and README.md "Version management" require the same tags in five
files. Today three of the five disagree:

| File | caddy tag | wafctl tag |
|---|---|---|
| `Makefile` | 3.97.2-2.11.4 | 2.101.3 |
| `deploy/edge/compose.yaml` | 3.97.2-2.11.4 | 2.101.3 |
| `compose.yaml` (root, servarr variant) | 3.97.0-2.11.4 | (no wafctl service) |
| `README.md` line 72 | 3.97.1-2.11.4 | 2.101.3 |
| `.github/workflows/build.yml` env | 3.97.0-2.11.4 | 2.97.0 |

Live state on the router: `erfianugrah/caddy:3.97.2-2.11.4` and
`erfianugrah/wafctl:2.101.3`. No caddy container runs on servarr, so the root
`compose.yaml` and root `Caddyfile` have no consumer.

Why it matters:

- The CI workflow publishes `${CADDY_IMAGE}:${CADDY_TAG}` and
  `${WAFCTL_IMAGE}:${WAFCTL_VERSION}` on every push to `main` that touches the
  filtered paths. With the env block stale, the next `wafctl/**` change
  rebuilds and re-pushes `wafctl:2.97.0` and `caddy:3.97.0-2.11.4` with
  current `main` content, then cosign-signs them. Tags become lies about
  what they contain.
- Anyone reading the README copies a tag that was never deployed.
- The "five files" rule is enforced by nobody; it broke without a test or a
  hook noticing.

## Fix plan

Order matters: put the overwrite guard in first, then sync, so the sync
commit itself cannot re-push a live tag.

### 1. Make CI refuse to overwrite an existing tag

In `.github/workflows/build.yml`, in both the `caddy` and `wafctl` jobs, add
a step after `Set image ref` / `Set image tag` and before the build:

```yaml
      - name: Refuse to overwrite a published tag
        run: |
          if docker manifest inspect "${{ steps.meta.outputs.full }}" > /dev/null 2>&1; then
            echo "::error::${{ steps.meta.outputs.full }} already exists on the registry. Bump the version."
            exit 1
          fi
```

`docker manifest inspect` needs no login for public repos. If the images are
private, move the step after `docker/login-action`.

### 2. Derive CI tags from the Makefile

Stop maintaining the versions in the workflow env block. Add two targets to
`Makefile`:

```make
print-caddy-tag: ## Print the caddy image tag (CI source of truth)
	@echo $(lastword $(subst :, ,$(CADDY_IMAGE)))

print-wafctl-tag: ## Print the wafctl image tag (CI source of truth)
	@echo $(WAFCTL_VERSION)
```

`WAFCTL_VERSION` is already computed in the Makefile from `WAFCTL_IMAGE`.
Then in the workflow replace the hard-coded `CADDY_TAG` and `WAFCTL_VERSION`
with a job that reads them:

```yaml
  versions:
    runs-on: ubuntu-latest
    outputs:
      caddy_tag: ${{ steps.v.outputs.caddy_tag }}
      wafctl_tag: ${{ steps.v.outputs.wafctl_tag }}
    steps:
      - uses: actions/checkout@v7
      - id: v
        run: |
          echo "caddy_tag=$(make -s print-caddy-tag)" >> "$GITHUB_OUTPUT"
          echo "wafctl_tag=$(make -s print-wafctl-tag)" >> "$GITHUB_OUTPUT"
```

and reference `needs.versions.outputs.caddy_tag` /
`needs.versions.outputs.wafctl_tag` in the `Set image ref` steps. Keep
`CADDY_VERSION` (upstream Caddy base) and `CRS_VERSION` in the env block;
they are build args, not publish tags, and `CADDY_VERSION` must equal the
trailing part of the caddy tag. Add that equality to the check in step 3.

The `-include .env.mk` line in the Makefile is harmless in CI (the file is
gitignored and absent).

### 3. Add a drift check

New file `scripts/version-check.sh`:

```bash
#!/usr/bin/env bash
# Fails if the image tags disagree across the tracked files.
set -euo pipefail
cd "$(dirname "$0")/.."

caddy_tag=$(make -s print-caddy-tag)
wafctl_tag=$(make -s print-wafctl-tag)
caddy_upstream=${caddy_tag##*-}
fail=0

check() { # file pattern label
  if ! grep -qE "$2" "$1"; then
    echo "DRIFT: $1 does not contain $3" >&2; fail=1
  fi
}

check deploy/edge/compose.yaml "image: erfianugrah/caddy:${caddy_tag//./\\.}$"  "caddy:${caddy_tag}"
check deploy/edge/compose.yaml "image: erfianugrah/wafctl:${wafctl_tag//./\\.}$" "wafctl:${wafctl_tag}"
check README.md "caddy:${caddy_tag//./\\.}"   "caddy:${caddy_tag}"
check README.md "wafctl:${wafctl_tag//./\\.}" "wafctl:${wafctl_tag}"
check .github/workflows/build.yml "CADDY_VERSION: \"${caddy_upstream//./\\.}\"" "CADDY_VERSION ${caddy_upstream}"
check Dockerfile "^ARG VERSION=${caddy_upstream//./\\.}$" "ARG VERSION=${caddy_upstream}"
if [ -f compose.yaml ]; then
  check compose.yaml "image: erfianugrah/caddy:${caddy_tag//./\\.}$" "caddy:${caddy_tag}"
fi

[ "$fail" -eq 0 ] && echo "versions in sync: caddy ${caddy_tag}, wafctl ${wafctl_tag}"
exit $fail
```

Wire it in three places:

- `Makefile`: `version-check: ## Fail on image tag drift` running the script,
  and make `build`, `push` and `restart` depend on it.
- `.github/workflows/build.yml`: a `version-check` job that the `caddy` and
  `wafctl` jobs `need`.
- `.git/hooks/pre-commit` (the existing SOPS hook): call the script when any
  of the tracked files is staged.

### 4. Decide the fate of the root `compose.yaml` and root `Caddyfile`

They describe the servarr Unraid layout (`/mnt/user`, `/mnt/cache`) and pin
`3.97.0`. servarr has no caddy container, and the servarr Caddyfile header
says that host became a routing hop on 2026-07-24. Either:

- delete both, update AGENTS.md/README.md to say `deploy/edge/` is the only
  deployment, and drop `compose.yaml` from the check script; or
- keep them, rename to `deploy/servarr/`, and let the check script cover
  them.

Deleting is the recommendation. The e2e stack has its own
`test/docker-compose.e2e.yml` and `test/Caddyfile.e2e`, so tests do not
depend on the root files. Check `rg -n 'compose.yaml|/Caddyfile' Makefile test/`
for stragglers before removing.

### 5. Sync the current values

With the guard from step 1 in place, set every remaining file to the live
values (`3.97.2-2.11.4` and `2.101.3`): README.md line 72, root
`compose.yaml` if kept. The workflow env block no longer holds publish tags
after step 2. Run `make version-check` and commit everything together:

```bash
git add Makefile scripts/version-check.sh .github/workflows/build.yml README.md compose.yaml
git commit -m "build: single-source image tags from the Makefile, add drift check"
git push
```

The push triggers CI. Because `3.97.2-2.11.4` and `2.101.3` already exist on
Docker Hub, the new guard should fail the publish jobs on purpose. That is
the expected outcome for a sync-only commit; the next real change bumps the
tag and publishes normally.

### 6. Update the docs

Rewrite README.md "Version management" to say: bump `CADDY_IMAGE` /
`WAFCTL_IMAGE` in the Makefile, mirror the tag in `deploy/edge/compose.yaml`
and the README example, run `make version-check`. Replace the "five files"
sentence in both AGENTS.md files with the same instruction.

## Verification

```bash
make version-check                       # exits 0, prints the two tags
make -s print-caddy-tag print-wafctl-tag # 3.97.2-2.11.4 / 2.101.3
git stash; sed -i 's/2\.101\.3/2.101.9/' README.md; make version-check; git checkout README.md; git stash pop
# the middle command must exit 1 with a DRIFT line
```

On GitHub: the `version-check` job is green and the publish jobs fail with
the "already exists" error for the sync commit.

## Rollback

Everything here is build tooling. `git revert` the commit; no deploy is
involved.
