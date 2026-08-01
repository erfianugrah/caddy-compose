package main

// ─── verify ────────────────────────────────────────────────────────

import (
	"regexp"
	"sort"
)

// parseConfiguredDirs extracts the unique per-site nuts Dir paths under
// ctrRoot from Caddyfile text. A site is only correctly persisted when
// its Dir sits inside the nuts configuration block (test/cache/README.md
// "Per-site storage"), so every configured Dir must resolve to a live
// on-disk DB.
func parseConfiguredDirs(caddyfile, ctrRoot string) []string {
	pattern := regexp.MustCompile(`Dir\s+(` + regexp.QuoteMeta(ctrRoot) + `/[a-z0-9-]+)`)
	seen := make(map[string]bool)
	var dirs []string
	for _, m := range pattern.FindAllStringSubmatch(caddyfile, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			dirs = append(dirs, m[1])
		}
	}
	sort.Strings(dirs)
	return dirs
}

// cmdVerify runs the hard storage-layout asserts against the live edge.
// Returns the process exit code: 0 when every assert passes, 1 otherwise.
func cmdVerify(e edge) int {
	fail := false
	pass := func(format string, a ...any) { e.printf("PASS  "+format, a...) }
	failf := func(format string, a ...any) {
		e.printf("FAIL  "+format, a...)
		fail = true
	}

	w, err := e.fallbackWarnings()
	switch {
	case err != nil:
		failf("fallback check: %v", err)
	case w == 0:
		pass("no in-memory fallback since container start")
	default:
		failf("%d handler(s) on in-memory default storage", w)
	}

	caddyfile, err := e.dockerExec("cat /etc/caddy/Caddyfile")
	if err != nil {
		failf("read container Caddyfile: %v", err)
	} else {
		dirs := parseConfiguredDirs(caddyfile, e.cfg.ctrRoot)
		if len(dirs) == 0 {
			failf("no per-site nuts Dir configured under %s", e.cfg.ctrRoot)
		}
		for _, dir := range dirs {
			if _, err := e.dockerExec("test -f " + dir + "/0.dat"); err != nil {
				failf("%s configured but no 0.dat", dir)
			} else {
				pass("%s has live DB", dir)
			}
		}
	}

	if _, err := e.dockerExec("test -e /tmp/souin-nuts/0.dat"); err == nil {
		failf("/tmp/souin-nuts/0.dat exists (Dir dropped from configuration - tmpfs DB)")
	} else {
		pass("no /tmp/souin-nuts default-path DB")
	}

	if fail {
		e.printf("VERIFY FAILED")
		return 1
	}
	e.printf("VERIFY OK")
	return 0
}
