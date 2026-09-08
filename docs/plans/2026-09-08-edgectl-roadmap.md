# Roadmap: edgectl control plane + ergo consolidation

Status: scaffolded 2026-09-08, after the caddy-native migration completed
(all 13 tasks, see `~/infra/router/docs/plans/2026-09-06-caddy-native-migration.md`).
This is the forward-looking plan. It sequences two coupled threads:
(A) the edgectl control plane (the real build-out) and (B) the ergo repo
consolidation (the structural home for it).

Feeds from: caddy-compose/PLAN.md "Direction Change" + "Suggested sequence",
the migration plan Task 13 follow-ups, and the settled JSON-PATCH design note.

---

## North star

The edge runs native on the router (done). wafctl becomes **edgectl**: an edge
control plane that owns host/site lifecycle over the Caddy admin JSON API,
backed by a durable store, surfaced by a reworked dashboard. The code lives in
a consolidated **ergo** monorepo. The WAF/CRS/challenge surface is removed
along the way (it is a maintenance sink, most sites run `waf_off`).

## Design invariants (settled, do not reopen)

- **Config layering**: the Caddyfile is the git-tracked declarative skeleton
  (nix `configFile`); the JSON admin API is edgectl's runtime control surface
  for the dynamic bits it owns; live JSON is derived, never git-tracked.
- **Granular PATCH only**: edgectl read-modify-writes individual
  `/config/apps/http/servers/.../routes/...` paths with ETag/If-Match. NEVER
  whole-Caddyfile `/load` (that is the 2026-09-07 clobber class).
- **Nix owns the host**: services, state dirs (tmpfiles), users. No manual
  chown/mkdir anywhere in the run path.
- **No CRS in the new world**: the policy-engine CRS pipeline is deleted, not
  ported. ddos-mitigator + caddy-l4 + body-matcher survive.

---

## Phase 0 - preflight (before any nuke)

- Inventory what actually uses the policy engine today (which of the 48 site
  blocks are `waf` vs `waf_off`). The nuke scope is exactly the `waf` sites.
- Confirm the surviving plugins (ddos-mitigator, body-matcher, l4) build
  standalone with policy-engine absent from caddy-edge.nix.
- Snapshot current behaviour for the sites that DO use WAF so the removal is
  reviewed against evidence.

## Phase 1 - WAF/CRS/challenge nuke (Direction Change item 1)

- Remove policy_engine from the site snippets that use it (swap to `waf_off`
  or a leaner `ddos`-only snippet). One PR, all sites.
- Remove policy-engine from `pkgs/caddy-edge.nix` + the Dockerfile manifest.
- Delete the CRS/challenge/session/JA4 code from wafctl (stores, handlers,
  dashboard pages) - the bulk of the LOC reduction.
- Nav prune in the dashboard; drop the dead pages.
- **Rename wafctl -> edgectl** in the same session (image name, service name,
  binary, DNS `waf.erfi.io` -> `edge.erfi.io` via knotctl, the pi skills).
  Doing it here avoids a second rename pass later.

## Phase 2 - ergo consolidation (structural)

Decision recorded 2026-09-07 (user): consolidate, monorepo over rename-only.
The compose deploy path is gone (native now), so `caddy-compose` is a misnomer.

- Create `~/infra/ergo/` as a single git repo (currently a workspace of
  independent repos). Fold in: caddy-compose (wafctl + waf-dashboard +
  Dockerfile manifest + tools/), caddy-body-matcher, caddy-policy-engine
  (archive or keep-readonly if fully nuked), caddy-ddos-mitigator, souin fork.
  Preserve history (git subtree/merge); do not squash away provenance.
- One flake output per buildable (caddy-edge, edgectl) so the router consumes
  a single `ergo` flake input instead of five - kills the version-pin drift
  (WAFCTL_VERSION was stale at 2.97.0 vs 2.101.3 in CI). Single module graph,
  single build.
- Update the router flake inputs (one `ergo` input), CI (one repo, one
  pipeline), and the pi skills' repo pointers.
- Archive the old standalone repos (read-only) once the monorepo builds and
  the router consumes it.

## Phase 3 - edgectl data layer + storage

- Phase-0 interface extraction on the surviving stores (PLAN.md section 3
  Phase 0) - define store interfaces before moving them.
- Storage migration per PLAN.md section 3 (config+event stores -> PostgreSQL,
  IP jail -> Valkey). REASSESS first: is Postgres+Valkey warranted at this
  scale, or is SQLite/embedded enough? That design predates the nuke and may
  be over-built for the post-nuke surface. Decide before building.
- Dashboard data-layer primitive (`useServerState`) - one fetch/cache/
  invalidate primitive all pages use, replacing per-page ad-hoc fetching.

## Phase 4 - edgectl control plane (the build-out)

- Caddy admin client: typed Go client for `/config/...` with ETag/If-Match,
  read-before-write, explicit path ownership (edgectl owns routes it created;
  the Caddyfile owns the skeleton; never cross-write).
- Site-lifecycle API on edgectl: add/remove/modify site -> PATCH the JSON ->
  knotctl DNS record. Replaces "edit Caddyfile + make caddy-reload + knotctl".
- Dashboard reads `GET /config/` as the source of truth for live routes;
  split DDoS/Overview pages.
- Reconciliation loop: on start and on a timer, edgectl diffs desired state
  (its store) against live `/config` and converges - detects drift (a human
  `/load`) instead of being blind to it.

## Phase 5 - host hygiene (small, independent)

- sops-nix for `/var/lib/secrets/edge.env` (fleet convention; the on-box 0600
  file is a stopgap).
- country.mmdb refresh timer (static Jul-21 file today).
- Adopt `fleet.docker-networks` on the router so `dockerBridges` derives from
  declared networks, not the hand-typed list.
- The 13 dependabot vulns on caddy-compose (npm, waf-dashboard) - mostly
  resolved by the Phase 1 nav prune / Phase 2 consolidation.

---

## Sequencing rationale

Phase 1 before 3/4: the nuke shrinks the surface the data layer + control
plane cover, and the rename rides the nuke (one churn, not two). Phase 2 can
run parallel to or just after Phase 1 - structural, not behavioural, and the
single flake input simplifies Phase 3/4's build. Phase 3 before 4: the control
plane needs the store interfaces + data layer, not the file-JSON stopgaps.

## Open decisions before each phase

- P1: exact list of `waf` sites to flip (from the Phase 0 inventory).
- P2: keep caddy-policy-engine archived-readonly, or delete outright.
- P3: PostgreSQL+Valkey vs SQLite/embedded - reassess against the post-nuke
  surface before building.
- P4: does edgectl own DNS too (knotctl integration) or just emit the record
  for manual/knotctl apply.
