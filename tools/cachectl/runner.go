package main

// ─── Command runner + edge bundle ──────────────────────────────────

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// config holds the deployment coordinates, overridable via env.
type config struct {
	sshHost   string
	container string
	hostRoot  string
	ctrRoot   string
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	return config{
		sshHost:   envOr("SSH_HOST", "router"),
		container: envOr("CONTAINER", "caddy"),
		hostRoot:  envOr("HOST_ROOT", "/var/lib/caddy/data/cache/nuts"),
		ctrRoot:   envOr("CTR_ROOT", "/data/cache/nuts"),
	}
}

// Runner executes a local command and returns its stdout. It exists so
// tests can script remote responses instead of shelling out.
type Runner interface {
	Run(name string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err,
				strings.TrimSpace(string(exitErr.Stderr)))
		}
		return string(out), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}

// edge bundles a Runner with the deployment config; all remote ops go
// through it. out is where command results are printed (os.Stdout in
// main, a buffer in tests). in is stdin (os.Stdin in main, a reader in tests).
type edge struct {
	cfg config
	r   Runner
	out io.Writer
	in  io.Reader
}

func (e edge) printf(format string, a ...any) {
	fmt.Fprintf(e.out, format+"\n", a...)
}

// ssh runs a shell script on the edge host.
func (e edge) ssh(script string) (string, error) {
	return e.r.Run("ssh", e.cfg.sshHost, script)
}

// dockerExec runs a shell script inside the caddy container on the edge.
func (e edge) dockerExec(script string) (string, error) {
	return e.ssh(fmt.Sprintf("docker exec %s sh -c %s", e.cfg.container, shellQuote(script)))
}

// shellQuote wraps s in single quotes for remote shell consumption.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fallbackWarnings counts in-memory-fallback warnings in the caddy log
// since the current container start.
func (e edge) fallbackWarnings() (int, error) {
	out, err := e.ssh(fmt.Sprintf(
		"docker logs %s --since $(docker inspect -f '{{.State.StartedAt}}' %s) 2>&1 | grep -c 'default storage' || true",
		e.cfg.container, e.cfg.container))
	if err != nil {
		return 0, fmt.Errorf("count fallback warnings: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("count fallback warnings: parse %q: %w", out, err)
	}
	return n, nil
}
