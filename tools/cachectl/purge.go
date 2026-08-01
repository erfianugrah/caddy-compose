package main

// ─── purge ─────────────────────────────────────────────────────────

import (
	"fmt"
	"regexp"
	"strings"
)

// validSiteName matches site names for per-site nuts dirs.
var validSiteName = regexp.MustCompile(`^[a-z0-9-]+$`)

// cmdPurge deletes a site's nuts DB directory and restarts the cache
// container. "all" removes and recreates the entire nuts root. THE ONLY
// working cache purge path (admin API + direct PURGE are non-functional).
func cmdPurge(e edge, site string, yes bool) error {
	var target string
	switch {
	case site == "all":
		target = e.cfg.ctrRoot
	case validSiteName.MatchString(site):
		target = e.cfg.ctrRoot + "/" + site
	default:
		return fmt.Errorf("invalid site name: %s", site)
	}

	if !yes {
		fmt.Printf("about to delete %s in container %s on %s and restart it. continue? [y/N] ",
			target, e.cfg.container, e.cfg.sshHost)
		var ans string
		_, err := fmt.Fscanln(e.in, &ans)
		if err != nil || strings.ToLower(ans) != "y" {
			return fmt.Errorf("aborted")
		}
	}

	if site == "all" {
		cmd := fmt.Sprintf("rm -rf %s; mkdir -p %s", e.cfg.ctrRoot, e.cfg.ctrRoot)
		if _, err := e.dockerExec(cmd); err != nil {
			return fmt.Errorf("purge all: %w", err)
		}
	} else {
		cmd := fmt.Sprintf("rm -rf %s", target)
		if _, err := e.dockerExec(cmd); err != nil {
			return fmt.Errorf("purge %s: %w", site, err)
		}
	}

	restartCmd := fmt.Sprintf("docker restart %s", e.cfg.container)
	if _, err := e.ssh(restartCmd); err != nil {
		return fmt.Errorf("restart %s: %w", e.cfg.container, err)
	}

	e.printf("purged %s + restarted %s (nuts re-creates dirs at open)", target, e.cfg.container)
	return nil
}
