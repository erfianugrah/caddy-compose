package main

// ─── status ────────────────────────────────────────────────────────

import "fmt"

// cmdStatus prints storage layout, per-site DB sizes, the in-memory
// fallback check, the tmpfs default-path check, and container stats.
func cmdStatus(e edge) error {
	e.printf("== per-site nuts DBs (%s) ==", e.cfg.hostRoot)
	out, err := e.ssh(fmt.Sprintf("du -sh %s/*/ 2>/dev/null || echo '(none)'", e.cfg.hostRoot))
	if err != nil {
		return fmt.Errorf("status: list DBs: %w", err)
	}
	e.printf("%s", out)

	e.printf("\n== fallback warnings since container start ==")
	w, err := e.fallbackWarnings()
	if err != nil {
		return err
	}
	if w == 0 {
		e.printf("  0 (all handlers on disk storage)")
	} else {
		e.printf("  %d  <-- HANDLERS ON IN-MEMORY STORAGE, entries die on restart", w)
	}

	e.printf("\n== tmpfs default-path check ==")
	out, err = e.dockerExec(fmt.Sprintf(
		"[ -e %s/../souin-nuts ] && echo present || true; "+
			"[ -e /tmp/souin-nuts/0.dat ] && echo '/tmp/souin-nuts/0.dat EXISTS - Dir trap, DB on tmpfs' "+
			"|| echo '  /tmp/souin-nuts: absent (good)'", e.cfg.ctrRoot))
	if err != nil {
		return fmt.Errorf("status: tmpfs check: %w", err)
	}
	e.printf("%s", out)

	e.printf("\n== container ==")
	out, err = e.ssh(fmt.Sprintf(
		"docker stats %s --no-stream --format '  MEM: {{.MemUsage}} ({{.MemPerc}})  CPU: {{.CPUPerc}}'; "+
			"docker ps --filter name=%s --format '  {{.Status}}'", e.cfg.container, e.cfg.container))
	if err != nil {
		return fmt.Errorf("status: container stats: %w", err)
	}
	e.printf("%s", out)
	return nil
}
