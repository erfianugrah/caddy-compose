package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
	"time"
)

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
		Stores     struct {
			WAFEvents struct {
				Events int `json:"events"`
			} `json:"waf_events"`
			AccessEvents struct {
				Events int `json:"events"`
			} `json:"access_events"`
			GeneralLogs struct {
				Events int `json:"events"`
			} `json:"general_logs"`
			GeoIP struct {
				MMDBLoaded bool `json:"mmdb_loaded"`
				APIEnabled bool `json:"api_enabled"`
			} `json:"geoip"`
			Exclusions struct {
				Count int `json:"count"`
			} `json:"exclusions"`
			Blocklist BlocklistStatsResponse `json:"blocklist"`
		} `json:"stores"`
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
	fmt.Fprintf(tw, "WAF Events:\t%d\n", health.Stores.WAFEvents.Events)
	fmt.Fprintf(tw, "Access Events:\t%d\n", health.Stores.AccessEvents.Events)
	fmt.Fprintf(tw, "General Logs:\t%d\n", health.Stores.GeneralLogs.Events)
	fmt.Fprintf(tw, "Exclusions:\t%d\n", health.Stores.Exclusions.Count)
	fmt.Fprintf(tw, "Blocklist IPs:\t%d\n", health.Stores.Blocklist.BlockedIPs)
	geoStatus := "disabled"
	if health.Stores.GeoIP.MMDBLoaded {
		geoStatus = "mmdb"
		if health.Stores.GeoIP.APIEnabled {
			geoStatus = "mmdb + api"
		}
	} else if health.Stores.GeoIP.APIEnabled {
		geoStatus = "api only"
	}
	fmt.Fprintf(tw, "GeoIP:\t%s\n", geoStatus)
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
	fmt.Fprintf(tw, "%sParanoia Level:\t%d\n", prefix, s.ParanoiaLevel)
	fmt.Fprintf(tw, "%sInbound Threshold:\t%d\n", prefix, s.InboundThreshold)
	fmt.Fprintf(tw, "%sOutbound Threshold:\t%d\n", prefix, s.OutboundThreshold)
	if s.DetectionOnly {
		fmt.Fprintf(tw, "%sDetection Only:\ttrue (evaluate + log, never block)\n", prefix)
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
