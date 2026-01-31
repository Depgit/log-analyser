package main

import (
	"fmt"
	"log-analyser/pkg/parser"
	"log-analyser/pkg/query"
	"log-analyser/pkg/report"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: log-analyser <logfile> [query]")
		os.Exit(1)
	}

	filePath := os.Args[1]
	queryString := ""
	if len(os.Args) > 2 {
		queryString = strings.Join(os.Args[2:], " ")
	}

	logType, err := parser.DetectFormat(filePath)
	if err != nil {
		fmt.Printf("Error detecting format: %v\n", err)
		os.Exit(1)
	}

	entries, err := parser.Parse(filePath, logType)
	if err != nil {
		fmt.Printf("Error parsing file: %v\n", err)
		os.Exit(1)
	}

	filteredEntries := query.Execute(entries, queryString)

	report.Generate(filteredEntries, logType, queryString)
}
