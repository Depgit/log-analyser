package main

import (
	"flag"
	"fmt"
	"log-analyser/pkg/parser"
	"log-analyser/pkg/query"
	"log-analyser/pkg/report"
	"os"
	"strings"
)

func main() {
	smartMode := flag.Bool("smart", true, "Enable smart natural language query parsing")
	sensitiveMode := flag.Bool("sensitive", false, "Enable case-sensitive matching")
	regexMode := flag.Bool("regex", false, "Enable regex matching")
	globMode := flag.Bool("glob", false, "Enable glob matching (e.g. *, ?)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: log-analyser [--smart] [--sensitive] [--regex] [--glob] <logfile> [query]")
		os.Exit(1)
	}

	filePath := args[0]
	queryString := ""
	if len(args) > 1 {
		queryString = strings.Join(args[1:], " ")
	}

	if *smartMode && queryString != "" {
		fmt.Println("Thinking...")
		originalQuery := queryString
		queryString = query.SmartParse(queryString)
		fmt.Printf("Original Query:   %s\n", originalQuery)
		fmt.Printf("Translated Query: %s\n", queryString)
	}

	logType, err := parser.DetectFormat(filePath)
	if err != nil {
		fmt.Printf("Error detecting format: %v\n", err)
		os.Exit(1)
	}

	// Pass the new modes to the parser and handle errors
	constraints, err := query.ParseConstraints(queryString, *regexMode, *globMode, *sensitiveMode)
	if err != nil {
		fmt.Printf("Query Error: %v\n", err)
		if *regexMode {
			fmt.Println("Tip: In regex mode, use '.*' for any characters (wildcard).")
		}
		os.Exit(1)
	}

	entries, err := parser.Parse(filePath, logType, constraints.MinLine, constraints.MaxLine)
	if err != nil {
		fmt.Printf("Error parsing file: %v\n", err)
		os.Exit(1)
	}

	// Filter entries
	filteredEntries := query.ExecuteWithConstraints(entries, constraints)

	// Generate report
	report.Generate(filteredEntries, logType, queryString)
}
