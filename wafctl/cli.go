package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// --- CLI subcommand dispatch ---

const cliUsage = `wafctl — WAF management tool for Caddy + Coraza

Usage:
  wafctl [command] [flags]

Commands:
  serve              Start the HTTP API server (default)
  version            Print version and exit
  health             Check API server health
  config get         Show current WAF configuration
  config set         Update WAF configuration (JSON on stdin or --file)
  rules list         List all policy exclusion rules
  rules get <id>     Get a specific rule by ID
  rules create       Create a rule (JSON on stdin or --file)
  rules delete <id>  Delete a rule by ID
  deploy             Deploy WAF config to Caddy (generate + reload)
  events             List recent WAF events
  ratelimit list     List all rate limit rules (alias: rl)
  ratelimit get <id> Get a rate limit rule by ID
  ratelimit create   Create a rate limit rule (JSON on stdin or --file)
  ratelimit delete   Delete a rate limit rule by ID
  ratelimit deploy   Deploy rate limit configs to Caddy
  ratelimit global   Show global rate limit settings
  lists list         List all managed lists (alias: ls)
  lists get <id>     Get a managed list by ID
  lists create       Create a managed list (JSON on stdin or --file)
  lists delete <id>  Delete a managed list by ID
  lists refresh <id> Refresh a URL-sourced managed list
  csp get            Show CSP configuration
  csp set            Update CSP configuration (JSON on stdin or --file)
  csp deploy         Deploy CSP configs to Caddy
  csp preview        Preview rendered CSP headers per service
  blocklist stats    Show IPsum blocklist statistics
  blocklist check    Check if an IP is blocklisted
  blocklist refresh  Refresh the blocklist from upstream

Flags:
  --addr string      API server address (default "http://localhost:8080")
  --json             Output raw JSON (default: human-readable tables)
  -h, --help         Show this help

When run without a command (or with "serve"), wafctl starts the HTTP API server.
All other commands are CLI clients that talk to a running wafctl server.
`

// cliFlags holds parsed CLI flags.
type cliFlags struct {
	addr   string
	asJSON bool
	file   string
}

func parseCLIFlags(args []string) (command []string, flags cliFlags) {
	flags.addr = envOr("WAFCTL_ADDR", "http://localhost:"+envOr("WAFCTL_PORT", "8080"))

	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 < len(args) {
				flags.addr = args[i+1]
				i++
			}
		case "--json":
			flags.asJSON = true
		case "--file", "-f":
			if i+1 < len(args) {
				flags.file = args[i+1]
				i++
			}
		case "-h", "--help":
			positional = append(positional, "help")
		default:
			if strings.HasPrefix(args[i], "--addr=") {
				flags.addr = strings.TrimPrefix(args[i], "--addr=")
			} else if strings.HasPrefix(args[i], "--file=") || strings.HasPrefix(args[i], "-f=") {
				flags.file = strings.SplitN(args[i], "=", 2)[1]
			} else {
				positional = append(positional, args[i])
			}
		}
	}
	return positional, flags
}

func runCLI(args []string) int {
	command, flags := parseCLIFlags(args)

	if len(command) == 0 {
		return runServe()
	}

	switch command[0] {
	case "serve":
		return runServe()
	case "version":
		return cliVersion()
	case "help":
		fmt.Print(cliUsage)
		return 0
	case "health":
		return cliHealth(flags)
	case "config":
		if len(command) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: wafctl config <get|set>\n")
			return 1
		}
		switch command[1] {
		case "get":
			return cliConfigGet(flags)
		case "set":
			return cliConfigSet(flags)
		default:
			fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", command[1])
			return 1
		}
	case "rules":
		if len(command) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: wafctl rules <list|get|create|delete> [id]\n")
			return 1
		}
		switch command[1] {
		case "list", "ls":
			return cliRulesList(flags)
		case "get":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl rules get <id>\n")
				return 1
			}
			return cliRulesGet(flags, command[2])
		case "create":
			return cliRulesCreate(flags)
		case "delete", "rm":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl rules delete <id>\n")
				return 1
			}
			return cliRulesDelete(flags, command[2])
		default:
			fmt.Fprintf(os.Stderr, "Unknown rules subcommand: %s\n", command[1])
			return 1
		}
	case "deploy":
		return cliDeploy(flags)
	case "events":
		return cliEvents(flags, command[1:])
	case "ratelimit", "rl":
		if len(command) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: wafctl ratelimit <list|get|create|delete|deploy|global> [id]\n")
			return 1
		}
		switch command[1] {
		case "list", "ls":
			return cliRateLimitList(flags)
		case "get":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl ratelimit get <id>\n")
				return 1
			}
			return cliRateLimitGet(flags, command[2])
		case "create":
			return cliRateLimitCreate(flags)
		case "delete", "rm":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl ratelimit delete <id>\n")
				return 1
			}
			return cliRateLimitDelete(flags, command[2])
		case "deploy":
			return cliRateLimitDeploy(flags)
		case "global":
			return cliRateLimitGlobal(flags)
		default:
			fmt.Fprintf(os.Stderr, "Unknown ratelimit subcommand: %s\n", command[1])
			return 1
		}
	case "lists", "ls":
		if len(command) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: wafctl lists <list|get|create|delete|refresh> [id]\n")
			return 1
		}
		switch command[1] {
		case "list", "ls":
			return cliListManagedLists(flags)
		case "get":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl lists get <id>\n")
				return 1
			}
			return cliGetManagedList(flags, command[2])
		case "create":
			return cliCreateManagedList(flags)
		case "delete", "rm":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl lists delete <id>\n")
				return 1
			}
			return cliDeleteManagedList(flags, command[2])
		case "refresh":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl lists refresh <id>\n")
				return 1
			}
			return cliRefreshManagedList(flags, command[2])
		default:
			fmt.Fprintf(os.Stderr, "Unknown lists subcommand: %s\n", command[1])
			return 1
		}
	case "csp":
		if len(command) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: wafctl csp <get|set|deploy|preview>\n")
			return 1
		}
		switch command[1] {
		case "get":
			return cliCSPGet(flags)
		case "set":
			return cliCSPSet(flags)
		case "deploy":
			return cliCSPDeploy(flags)
		case "preview":
			return cliCSPPreview(flags)
		default:
			fmt.Fprintf(os.Stderr, "Unknown csp subcommand: %s\n", command[1])
			return 1
		}
	case "blocklist":
		if len(command) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: wafctl blocklist <stats|check|refresh>\n")
			return 1
		}
		switch command[1] {
		case "stats":
			return cliBlocklistStats(flags)
		case "check":
			if len(command) < 3 {
				fmt.Fprintf(os.Stderr, "Usage: wafctl blocklist check <ip>\n")
				return 1
			}
			return cliBlocklistCheck(flags, command[2])
		case "refresh":
			return cliBlocklistRefresh(flags)
		default:
			fmt.Fprintf(os.Stderr, "Unknown blocklist subcommand: %s\n", command[1])
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'wafctl help' for usage.\n", command[0])
		return 1
	}
}

// --- HTTP client helpers ---

func cliGet(flags cliFlags, path string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(flags.addr + path)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", flags.addr, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func cliPost(flags cliFlags, path string, payload []byte) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	var body io.Reader
	if payload != nil {
		body = strings.NewReader(string(payload))
	} else {
		body = strings.NewReader("")
	}
	resp, err := client.Post(flags.addr+path, "application/json", body)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", flags.addr, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return data, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func cliPut(flags cliFlags, path string, payload []byte) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPut, flags.addr+path, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", flags.addr, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return data, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func cliDelete(flags cliFlags, path string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodDelete, flags.addr+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", flags.addr, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return data, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func readInput(flags cliFlags) ([]byte, error) {
	if flags.file != "" {
		return os.ReadFile(flags.file)
	}
	return io.ReadAll(os.Stdin)
}

func printJSON(data []byte) {
	var v interface{}
	if json.Unmarshal(data, &v) == nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		enc.Encode(v)
	} else {
		os.Stdout.Write(data)
		fmt.Println()
	}
}
