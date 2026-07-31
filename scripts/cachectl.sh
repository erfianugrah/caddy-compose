#!/usr/bin/env bash
# cachectl - ops tool for the edge HTTP cache (cache-handler/Souin + nuts)
# on the MS-01 edge router.
#
# Why this exists: the souin admin API permanently returns [] and admin
# PURGE is a no-op (test/cache/README.md quirk #3), direct PURGE only works
# when the ORIGIN cooperates (quirk #4), and the storage layout has three
# upstream traps (per-site storage section). All live cache inspection and
# reclaim therefore goes through the filesystem + caddy logs, which is what
# this script wraps.
#
# Usage:
#   cachectl status            storage layout, per-site DB sizes, fallback check, RAM
#   cachectl verify            hard asserts (exit 1 on any failure): no in-memory
#                              fallbacks, per-site DBs at configured paths, no
#                              /tmp/souin-nuts default-path DB
#   cachectl probe <url> [url..] request each URL twice via the edge, print
#                              Cache-Status of both (expect fwd/stored then hit;NUTS)
#   cachectl purge <site|all>  delete /data/cache/nuts/<site> + restart caddy.
#                              THE ONLY working purge. -y to skip confirmation.
#
# Env overrides: SSH_HOST (nixos), CONTAINER (caddy), EDGE_IP (auto-detected
# via ifconfig.me from the edge, cached per run).
set -u -o pipefail

SSH_HOST="${SSH_HOST:-nixos}"
CONTAINER="${CONTAINER:-caddy}"
HOST_ROOT="${HOST_ROOT:-/var/lib/caddy/data/cache/nuts}"
CTR_ROOT="${CTR_ROOT:-/data/cache/nuts}"

edge_ip() {
	ssh "$SSH_HOST" 'curl -s -4 --max-time 5 ifconfig.me'
}

# count of in-memory-fallback warnings since the current container start
fallback_warnings() {
	ssh "$SSH_HOST" "docker logs $CONTAINER --since \$(docker inspect -f '{{.State.StartedAt}}' $CONTAINER) 2>&1 | grep -c 'default storage' || true"
}

cmd_status() {
	echo "== per-site nuts DBs ($HOST_ROOT) =="
	ssh "$SSH_HOST" "du -sh $HOST_ROOT/*/ 2>/dev/null || echo '(none)'"
	echo
	echo "== fallback warnings since container start =="
	w=$(fallback_warnings)
	if [ "$w" = 0 ]; then echo "  0 (all handlers on disk storage)"; else echo "  $w  <-- HANDLERS ON IN-MEMORY STORAGE, entries die on restart"; fi
	echo
	echo "== tmpfs default-path check =="
	ssh "$SSH_HOST" "docker exec $CONTAINER sh -c '[ -e $CTR_ROOT/../souin-nuts ] && echo present || true; [ -e /tmp/souin-nuts/0.dat ] && echo \"/tmp/souin-nuts/0.dat EXISTS - Dir trap, DB on tmpfs\" || echo \"  /tmp/souin-nuts: absent (good)\"'"
	echo
	echo "== container =="
	ssh "$SSH_HOST" "docker stats $CONTAINER --no-stream --format '  MEM: {{.MemUsage}} ({{.MemPerc}})  CPU: {{.CPUPerc}}'; docker ps --filter name=$CONTAINER --format '  {{.Status}}'"
}

cmd_verify() {
	fail=0
	w=$(fallback_warnings)
	if [ "$w" = 0 ]; then echo "PASS  no in-memory fallback since container start"; else echo "FAIL  $w handler(s) on in-memory default storage"; fail=1; fi
	# every configured Dir in the Caddyfile must exist with a live segment file
	configured=$(ssh "$SSH_HOST" "docker exec $CONTAINER grep -oE 'Dir $CTR_ROOT/[a-z0-9-]+' /etc/caddy/Caddyfile | awk '{print \$2}' | sort -u")
	for dir in $configured; do
		if ssh "$SSH_HOST" "docker exec $CONTAINER test -f $dir/0.dat"; then
			echo "PASS  $dir has live DB"
		else
			echo "FAIL  $dir configured but no 0.dat"; fail=1
		fi
	done
	if ssh "$SSH_HOST" "docker exec $CONTAINER test -e /tmp/souin-nuts/0.dat"; then
		echo "FAIL  /tmp/souin-nuts/0.dat exists (Dir dropped from configuration - tmpfs DB)"; fail=1
	else
		echo "PASS  no /tmp/souin-nuts default-path DB"
	fi
	[ "$fail" = 0 ] && echo "VERIFY OK" || { echo "VERIFY FAILED"; exit 1; }
}

cmd_probe() {
	[ $# -ge 1 ] || { echo "usage: cachectl probe <url> [url...]" >&2; exit 2; }
	ip=$(edge_ip)
	for url in "$@"; do
		host=$(printf '%s' "$url" | sed -E 's|^https?://([^/]+).*|\1|')
		echo "== $url (via $ip) =="
		for n in 1 2; do
			cs=$(curl -s -o /dev/null -D - --resolve "$host:443:$ip" "$url" | tr -d '\r' | grep -i '^cache-status:' || echo '  (no cache-status header - not a cached route)')
			echo "  #$n  $cs"
		done
	done
	echo "expect: #1 fwd=uri-miss;stored (or hit), #2 hit with detail=NUTS. detail=DEFAULT means in-memory fallback."
}

cmd_purge() {
	[ $# -ge 1 ] || { echo "usage: cachectl purge <site|all> [-y]" >&2; exit 2; }
	site="$1"; yes="${2:-}"
	case "$site" in
		all) target="$CTR_ROOT" ;;
		*[!.a-z0-9-]*) echo "invalid site name: $site" >&2; exit 2 ;;
		*) target="$CTR_ROOT/$site" ;;
	esac
	if [ "$yes" != "-y" ]; then
		printf 'about to delete %s in container %s on %s and restart it. continue? [y/N] ' "$target" "$CONTAINER" "$SSH_HOST"
		read -r ans; [ "$ans" = y ] || { echo aborted; exit 1; }
	fi
	if [ "$site" = all ]; then
		ssh "$SSH_HOST" "docker exec $CONTAINER sh -c 'rm -rf $CTR_ROOT; mkdir -p $CTR_ROOT'"
	else
		ssh "$SSH_HOST" "docker exec $CONTAINER rm -rf $target"
	fi
	ssh "$SSH_HOST" "docker restart $CONTAINER"
	echo "purged $target + restarted $CONTAINER (nuts re-creates dirs at open)"
}

case "${1:-}" in
	status) cmd_status ;;
	verify) cmd_verify ;;
	probe) shift; cmd_probe "$@" ;;
	purge) shift; cmd_purge "$@" ;;
	*) sed -n '2,25p' "$0"; exit 2 ;;
esac
