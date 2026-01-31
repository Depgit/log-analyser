package report

import (
	"fmt"
	"log-analyser/pkg/parser"
)

func Generate(entries []parser.LogEntry, format parser.LogType, query string) {
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Log Format Detected: %s\n", format)
	if query != "" {
		fmt.Printf("Query: \"%s\"\n", query)
	}
	fmt.Printf("Total Matches: %d\n", len(entries))
	fmt.Println("--------------------------------------------------")

	for _, entry := range entries {
		fmt.Println(entry.Raw)
	}
	fmt.Println("--------------------------------------------------")
}
