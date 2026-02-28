package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
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

// --- Subcommand implementations ---

func cliVersion() int {
	fmt.Printf("wafctl %s\n", version)
	return 0
}

func cliHealth(flags cliFlags) int {
	data, err := cliGet(flags, "/api/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var health struct {
		Status     string `json:"status"`
		Version    string `json:"version"`
		CRSVersion string `json:"crs_version"`
		Uptime     string `json:"uptime"`
		Events     int    `json:"events"`
		Exclusions int    `json:"exclusions"`
		GeoIPDB    string `json:"geoip_db"`
		Blocklist  struct {
			Total int `json:"total_ips"`
		} `json:"blocklist"`
	}
	if err := json.Unmarshal(data, &health); err != nil {
		printJSON(data)
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Status:\t%s\n", health.Status)
	fmt.Fprintf(tw, "Version:\t%s\n", health.Version)
	fmt.Fprintf(tw, "CRS:\t%s\n", health.CRSVersion)
	fmt.Fprintf(tw, "Uptime:\t%s\n", health.Uptime)
	fmt.Fprintf(tw, "Events:\t%d\n", health.Events)
	fmt.Fprintf(tw, "Exclusions:\t%d\n", health.Exclusions)
	fmt.Fprintf(tw, "GeoIP DB:\t%s\n", health.GeoIPDB)
	fmt.Fprintf(tw, "Blocklist IPs:\t%d\n", health.Blocklist.Total)
	tw.Flush()
	return 0
}

func cliConfigGet(flags cliFlags) int {
	data, err := cliGet(flags, "/api/config")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var cfg WAFConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		printJSON(data)
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Defaults:\n")
	printWAFSettings(tw, "  ", cfg.Defaults)
	if len(cfg.Services) > 0 {
		fmt.Fprintf(tw, "\nPer-Service Overrides:\n")
		for name, svc := range cfg.Services {
			fmt.Fprintf(tw, "\n  [%s]\n", name)
			printWAFSettings(tw, "    ", svc)
		}
	}
	tw.Flush()
	return 0
}

func printWAFSettings(tw *tabwriter.Writer, prefix string, s WAFServiceSettings) {
	fmt.Fprintf(tw, "%sMode:\t%s\n", prefix, s.Mode)
	fmt.Fprintf(tw, "%sParanoia Level:\t%d\n", prefix, s.ParanoiaLevel)
	fmt.Fprintf(tw, "%sInbound Threshold:\t%d\n", prefix, s.InboundThreshold)
	fmt.Fprintf(tw, "%sOutbound Threshold:\t%d\n", prefix, s.OutboundThreshold)
	if len(s.DisabledGroups) > 0 {
		fmt.Fprintf(tw, "%sDisabled Groups:\t%s\n", prefix, strings.Join(s.DisabledGroups, ", "))
	}
}

func cliConfigSet(flags cliFlags) int {
	payload, err := readInput(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		return 1
	}
	data, err := cliPut(flags, "/api/config", payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
	} else {
		fmt.Println("Configuration updated.")
	}
	return 0
}

func cliRulesList(flags cliFlags) int {
	data, err := cliGet(flags, "/api/exclusions")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var rules []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		printJSON(data)
		return 0
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tNAME\tTYPE\tENABLED\n")
	fmt.Fprintf(tw, "--\t----\t----\t-------\n")
	for _, r := range rules {
		enabled := "yes"
		if !r.Enabled {
			enabled = "no"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Type, enabled)
	}
	tw.Flush()
	fmt.Printf("\n%d rule(s)\n", len(rules))
	return 0
}

func cliRulesGet(flags cliFlags, id string) int {
	data, err := cliGet(flags, "/api/exclusions/"+url.PathEscape(id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	printJSON(data)
	return 0
}

func cliRulesCreate(flags cliFlags) int {
	payload, err := readInput(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		return 1
	}
	data, err := cliPost(flags, "/api/exclusions", payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
	} else {
		var created struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &created) == nil {
			fmt.Printf("Rule created: %s (%s)\n", created.Name, created.ID)
		} else {
			printJSON(data)
		}
	}
	return 0
}

func cliRulesDelete(flags cliFlags, id string) int {
	_, err := cliDelete(flags, "/api/exclusions/"+url.PathEscape(id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Printf("Rule %s deleted.\n", id)
	return 0
}

func cliDeploy(flags cliFlags) int {
	fmt.Print("Deploying WAF configuration to Caddy... ")
	data, err := cliPost(flags, "/api/config/deploy", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		return 1
	}
	if flags.asJSON {
		fmt.Println()
		printJSON(data)
		return 0
	}
	var result struct {
		Status      string `json:"status"`
		Fingerprint string `json:"fingerprint"`
	}
	if json.Unmarshal(data, &result) == nil {
		fmt.Printf("done\nStatus: %s\nFingerprint: %s\n", result.Status, result.Fingerprint)
	} else {
		fmt.Println("done")
		printJSON(data)
	}
	return 0
}

func cliEvents(flags cliFlags, args []string) int {
	params := url.Values{}
	params.Set("hours", "24")
	params.Set("limit", "50")

	// Parse optional flags: --hours, --limit, --service, --type, --client, --method
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--hours":
			if i+1 < len(args) {
				params.Set("hours", args[i+1])
				i++
			}
		case "--limit":
			if i+1 < len(args) {
				params.Set("limit", args[i+1])
				i++
			}
		case "--service":
			if i+1 < len(args) {
				params.Set("service", args[i+1])
				i++
			}
		case "--type":
			if i+1 < len(args) {
				params.Set("event_type", args[i+1])
				i++
			}
		case "--client":
			if i+1 < len(args) {
				params.Set("client", args[i+1])
				i++
			}
		case "--method":
			if i+1 < len(args) {
				params.Set("method", args[i+1])
				i++
			}
		case "--rule":
			if i+1 < len(args) {
				params.Set("rule_name", args[i+1])
				i++
			}
		}
	}

	data, err := cliGet(flags, "/api/events?"+params.Encode())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var resp struct {
		Total  int `json:"total"`
		Events []struct {
			ID        string `json:"id"`
			Timestamp string `json:"timestamp"`
			EventType string `json:"event_type"`
			Service   string `json:"service"`
			ClientIP  string `json:"client_ip"`
			Method    string `json:"method"`
			URI       string `json:"uri"`
			RuleID    int    `json:"rule_id"`
		} `json:"events"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		printJSON(data)
		return 0
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "TIME\tTYPE\tSERVICE\tCLIENT\tMETHOD\tURI\tRULE\n")
	fmt.Fprintf(tw, "----\t----\t-------\t------\t------\t---\t----\n")
	for _, e := range resp.Events {
		ts := e.Timestamp
		if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
			ts = t.Format("15:04:05")
		}
		uri := e.URI
		if len(uri) > 40 {
			uri = uri[:37] + "..."
		}
		rule := ""
		if e.RuleID > 0 {
			rule = fmt.Sprintf("%d", e.RuleID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			ts, e.EventType, e.Service, e.ClientIP, e.Method, uri, rule)
	}
	tw.Flush()
	fmt.Printf("\nShowing %d of %d event(s)\n", len(resp.Events), resp.Total)
	return 0
}

// --- Rate Limit CLI subcommands ---

func cliRateLimitList(flags cliFlags) int {
	data, err := cliGet(flags, "/api/rate-rules")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var rules []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Service  string `json:"service"`
		Key      string `json:"key"`
		Events   int    `json:"events"`
		Window   string `json:"window"`
		Action   string `json:"action"`
		Priority int    `json:"priority"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		printJSON(data)
		return 0
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tNAME\tSERVICE\tKEY\tEVENTS\tWINDOW\tACTION\tENABLED\n")
	fmt.Fprintf(tw, "--\t----\t-------\t---\t------\t------\t------\t-------\n")
	for _, r := range rules {
		enabled := "yes"
		if !r.Enabled {
			enabled = "no"
		}
		action := r.Action
		if action == "" {
			action = "deny"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			r.ID, r.Name, r.Service, r.Key, r.Events, r.Window, action, enabled)
	}
	tw.Flush()
	fmt.Printf("\n%d rule(s)\n", len(rules))
	return 0
}

func cliRateLimitGet(flags cliFlags, id string) int {
	data, err := cliGet(flags, "/api/rate-rules/"+url.PathEscape(id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	printJSON(data)
	return 0
}

func cliRateLimitCreate(flags cliFlags) int {
	payload, err := readInput(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		return 1
	}
	data, err := cliPost(flags, "/api/rate-rules", payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
	} else {
		var created struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(data, &created) == nil {
			fmt.Printf("Rate limit rule created: %s (%s)\n", created.Name, created.ID)
		} else {
			printJSON(data)
		}
	}
	return 0
}

func cliRateLimitDelete(flags cliFlags, id string) int {
	_, err := cliDelete(flags, "/api/rate-rules/"+url.PathEscape(id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Printf("Rate limit rule %s deleted.\n", id)
	return 0
}

func cliRateLimitDeploy(flags cliFlags) int {
	fmt.Print("Deploying rate limit configuration to Caddy... ")
	data, err := cliPost(flags, "/api/rate-rules/deploy", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		return 1
	}
	if flags.asJSON {
		fmt.Println()
		printJSON(data)
		return 0
	}
	var result struct {
		Status  string   `json:"status"`
		Message string   `json:"message"`
		Files   []string `json:"files"`
	}
	if json.Unmarshal(data, &result) == nil {
		fmt.Printf("done\nStatus: %s\nFiles: %d\n", result.Status, len(result.Files))
		if result.Message != "" {
			fmt.Println(result.Message)
		}
	} else {
		fmt.Println("done")
		printJSON(data)
	}
	return 0
}

func cliRateLimitGlobal(flags cliFlags) int {
	data, err := cliGet(flags, "/api/rate-rules/global")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var cfg struct {
		Jitter        float64 `json:"jitter"`
		SweepInterval string  `json:"sweep_interval"`
		Distributed   bool    `json:"distributed"`
		ReadInterval  string  `json:"read_interval"`
		WriteInterval string  `json:"write_interval"`
		PurgeAge      string  `json:"purge_age"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		printJSON(data)
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Jitter:\t%.2f\n", cfg.Jitter)
	fmt.Fprintf(tw, "Sweep Interval:\t%s\n", orDefault(cfg.SweepInterval, "(default)"))
	fmt.Fprintf(tw, "Distributed:\t%v\n", cfg.Distributed)
	if cfg.Distributed {
		fmt.Fprintf(tw, "Read Interval:\t%s\n", orDefault(cfg.ReadInterval, "(default)"))
		fmt.Fprintf(tw, "Write Interval:\t%s\n", orDefault(cfg.WriteInterval, "(default)"))
		fmt.Fprintf(tw, "Purge Age:\t%s\n", orDefault(cfg.PurgeAge, "(default)"))
	}
	tw.Flush()
	return 0
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func cliBlocklistStats(flags cliFlags) int {
	data, err := cliGet(flags, "/api/blocklist/stats")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var stats struct {
		TotalIPs int    `json:"total_ips"`
		Updated  string `json:"updated"`
		FilePath string `json:"file_path"`
		FileSize int64  `json:"file_size"`
	}
	if err := json.Unmarshal(data, &stats); err != nil {
		printJSON(data)
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Total IPs:\t%d\n", stats.TotalIPs)
	fmt.Fprintf(tw, "Updated:\t%s\n", stats.Updated)
	fmt.Fprintf(tw, "File:\t%s\n", stats.FilePath)
	fmt.Fprintf(tw, "File Size:\t%d bytes\n", stats.FileSize)
	tw.Flush()
	return 0
}

func cliBlocklistCheck(flags cliFlags, ip string) int {
	data, err := cliGet(flags, "/api/blocklist/check/"+url.PathEscape(ip))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var result struct {
		IP      string `json:"ip"`
		Blocked bool   `json:"blocked"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		printJSON(data)
		return 0
	}
	if result.Blocked {
		fmt.Printf("%s is BLOCKED (in IPsum blocklist)\n", result.IP)
		return 1 // Non-zero exit for blocked IPs (useful in scripts)
	}
	fmt.Printf("%s is not blocked\n", result.IP)
	return 0
}

func cliBlocklistRefresh(flags cliFlags) int {
	fmt.Print("Refreshing blocklist from upstream... ")
	data, err := cliPost(flags, "/api/blocklist/refresh", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		return 1
	}
	if flags.asJSON {
		fmt.Println()
		printJSON(data)
		return 0
	}
	fmt.Println("done")
	var result struct {
		TotalIPs int    `json:"total_ips"`
		Status   string `json:"status"`
	}
	if json.Unmarshal(data, &result) == nil && result.TotalIPs > 0 {
		fmt.Printf("Blocklist refreshed: %d IPs loaded\n", result.TotalIPs)
	}
	return 0
}

// ─── CSP CLI ────────────────────────────────────────────────────────────────

func cliCSPGet(flags cliFlags) int {
	data, err := cliGet(flags, "/api/csp")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	printJSON(data)
	return 0
}

func cliCSPSet(flags cliFlags) int {
	body, err := readInput(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	data, err := cliPut(flags, "/api/csp", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	printJSON(data)
	return 0
}

func cliCSPDeploy(flags cliFlags) int {
	fmt.Print("Deploying CSP configs... ")
	data, err := cliPost(flags, "/api/csp/deploy", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		return 1
	}
	if flags.asJSON {
		fmt.Println()
		printJSON(data)
		return 0
	}
	fmt.Println("done")
	var result CSPDeployResponse
	if json.Unmarshal(data, &result) == nil {
		fmt.Printf("Generated %d files, reloaded: %v\n", len(result.Files), result.Reloaded)
	}
	return 0
}

func cliCSPPreview(flags cliFlags) int {
	data, err := cliGet(flags, "/api/csp/preview")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	printJSON(data)
	return 0
}
