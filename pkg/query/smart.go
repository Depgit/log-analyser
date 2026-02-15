package query

import (
	"strings"
)

// SmartParse transforms a natural language query into a structured query string
// compatible with the strict parser.
// It handles:
// - Stop word removal ("show me", "find", etc.)
// - Operator translation ("and" -> "&&", "or" -> "||", "not" -> "!")
// - Heuristic phrase detection (optional, for now relying on implicit AND)
func SmartParse(input string) string {
	// 1. Tokenize by space to process words
	words := strings.Fields(input)
	var processed []string

	stopWords := map[string]bool{
		"show": true, "me": true, "find": true, "search": true, "look": true, "for": true,
		"the": true, "a": true, "an": true, "log": true, "logs": true, "entries": true,
		"containing": true, "where": true, "which": true, "have": true, "has": true,
		"are": true, "is": true, "of": true, "about": true, "related": true, "to": true,
	}

	for _, word := range words {
		lower := strings.ToLower(word)

		// Operator translation
		if lower == "and" {
			processed = append(processed, "&&")
			continue
		}
		if lower == "or" {
			processed = append(processed, "||")
			continue
		}
		if lower == "not" {
			processed = append(processed, "!")
			continue
		}
		if lower == "except" {
			processed = append(processed, "!") // Treat as NOT (Implicit AND NOT)
			continue
		}
		if lower == "but" {
			processed = append(processed, "&&")
			continue
		}
		if lower == "with" {
			processed = append(processed, "&&")
			continue
		}
		if lower == "without" {
			processed = append(processed, "&&", "!")
			continue
		}

		if stopWords[lower] {
			continue
		}

		processed = append(processed, word)
	}

	return strings.Join(processed, " ")
}
