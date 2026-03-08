package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
)

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

	var stats BlocklistStatsResponse
	if err := json.Unmarshal(data, &stats); err != nil {
		printJSON(data)
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Blocked IPs:\t%d\n", stats.BlockedIPs)
	fmt.Fprintf(tw, "Min Score:\t%d\n", stats.MinScore)
	fmt.Fprintf(tw, "Source:\t%s\n", stats.Source)
	fmt.Fprintf(tw, "Updated:\t%s\n", stats.LastUpdated)
	fmt.Fprintf(tw, "File:\t%s\n", stats.FilePath)
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
