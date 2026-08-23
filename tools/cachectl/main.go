package main

// ─── cachectl ──────────────────────────────────────────────────────
//
// Ops CLI for the edge HTTP cache (cache-handler/Souin + nuts) on the
// MS-01 edge router. Replaces scripts/cachectl.sh.
//
// Why this exists: the souin admin API permanently returns [] and admin
// PURGE is a no-op (test/cache/README.md quirk #3), direct PURGE only
// works when the ORIGIN cooperates (quirk #4), and the storage layout
// has three upstream traps (per-site storage section). All live cache
// inspection and reclaim therefore goes through the filesystem + caddy
// logs, which is what this tool wraps.
//
// Usage:
//   cachectl status              storage layout, per-site DB sizes, fallback check, RAM
//   cachectl verify              hard asserts (exit 1 on any failure)
//   cachectl probe <url> [url..] request each URL twice via the edge, print Cache-Status
//   cachectl purge <site|all>    delete <ctrRoot>/<site> + restart caddy (-y skips confirm)
//
// Env overrides: SSH_HOST (router), CONTAINER (caddy), EDGE_IP (auto-detected
// via ifconfig.me from the edge), HOST_ROOT, CTR_ROOT.

import (
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	e := edge{cfg: loadConfig(), r: execRunner{}, out: os.Stdout, in: os.Stdin}

	var err error
	switch os.Args[1] {
	case "status":
		err = cmdStatus(e)
	case "verify":
		os.Exit(cmdVerify(e))
	case "probe":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: cachectl probe <url> [url...]")
			os.Exit(2)
		}
		err = cmdProbe(e, os.Args[2:])
	case "purge":
		site, yes := parsePurgeArgs(os.Args[2:])
		if site == "" {
			fmt.Fprintln(os.Stderr, "usage: cachectl purge <site|all> [-y]")
			os.Exit(2)
		}
		err = cmdPurge(e, site, yes)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `cachectl - ops CLI for the edge HTTP cache (Souin + nuts) on the MS-01 edge

Usage:
  cachectl status              storage layout, per-site DB sizes, fallback check, RAM
  cachectl verify              hard asserts (exit 1 on any failure)
  cachectl probe <url> [url..] request each URL twice via the edge, print Cache-Status
  cachectl purge <site|all>    delete the site's nuts dir + restart caddy (-y skips confirm)

Env overrides: SSH_HOST (router), CONTAINER (caddy), EDGE_IP, HOST_ROOT, CTR_ROOT`)
}

// parsePurgeArgs extracts the site name and -y flag from purge args.
func parsePurgeArgs(args []string) (site string, yes bool) {
	for _, a := range args {
		if a == "-y" {
			yes = true
		} else if site == "" {
			site = a
		}
	}
	return site, yes
}
