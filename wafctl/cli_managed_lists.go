package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
)

// --- Managed Lists CLI subcommands ---

func cliListManagedLists(flags cliFlags) int {
	data, err := cliGet(flags, "/api/lists")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if flags.asJSON {
		printJSON(data)
		return 0
	}

	var lists []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		Source    string `json:"source"`
		ItemCount int    `json:"item_count"`
	}
	if err := json.Unmarshal(data, &lists); err != nil {
		printJSON(data)
		return 0
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tNAME\tKIND\tSOURCE\tITEMS\n")
	fmt.Fprintf(tw, "--\t----\t----\t------\t-----\n")
	for _, l := range lists {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n",
			l.ID, l.Name, l.Kind, l.Source, l.ItemCount)
	}
	tw.Flush()
	fmt.Printf("\n%d list(s)\n", len(lists))
	return 0
}

func cliGetManagedList(flags cliFlags, id string) int {
	data, err := cliGet(flags, "/api/lists/"+url.PathEscape(id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	printJSON(data)
	return 0
}

func cliCreateManagedList(flags cliFlags) int {
	payload, err := readInput(flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		return 1
	}
	data, err := cliPost(flags, "/api/lists", payload)
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
			fmt.Printf("Managed list created: %s (%s)\n", created.Name, created.ID)
		} else {
			printJSON(data)
		}
	}
	return 0
}

func cliDeleteManagedList(flags cliFlags, id string) int {
	_, err := cliDelete(flags, "/api/lists/"+url.PathEscape(id))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Printf("Managed list %s deleted.\n", id)
	return 0
}

func cliRefreshManagedList(flags cliFlags, id string) int {
	fmt.Print("Refreshing managed list from URL... ")
	data, err := cliPost(flags, "/api/lists/"+url.PathEscape(id)+"/refresh", nil)
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
		Name      string `json:"name"`
		ItemCount int    `json:"item_count"`
	}
	if json.Unmarshal(data, &result) == nil {
		fmt.Printf("List %q refreshed: %d items\n", result.Name, result.ItemCount)
	}
	return 0
}
