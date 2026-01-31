package query

import (
	"fmt"
	"log-analyser/pkg/parser"
	"strings"
)

// Execute filters the log entries based on the user query string
// It supports multi-keyword matching (AND logic) and ignores common stop words.
// Constraints holds the parsed query requirements
type Constraints struct {
	MinLine  int
	MaxLine  int
	Keywords []string
}

// ParseConstraints parses the query string to extract line constraints and keywords
func ParseConstraints(queryString string) Constraints {
	if queryString == "" {
		return Constraints{MinLine: -1, MaxLine: -1, Keywords: nil}
	}

	minLine, maxLine := -1, -1

	// 1b. Check for Line Number queries
	// patterns: "after line X", "between line X and Y"
	lowerQuery := strings.ToLower(queryString)

	// Simple parsing for "after line <num>"
	if strings.Contains(lowerQuery, "after line") {
		parts := strings.Fields(queryString)
		for i, p := range parts {
			if strings.ToLower(p) == "line" && i+1 < len(parts) {
				// Try parsing next word as number
				var num int
				if _, err := fmt.Sscanf(parts[i+1], "%d", &num); err == nil {
					minLine = num
				}
			}
		}
	} else if strings.Contains(lowerQuery, "between line") {
		// "between line <X> and <Y>"
		// Very basic parsing
		parts := strings.Fields(queryString)
		nums := []int{}
		for _, p := range parts {
			var num int
			if _, err := fmt.Sscanf(p, "%d", &num); err == nil {
				nums = append(nums, num)
			}
		}
		if len(nums) >= 2 {
			minLine = nums[0]
			maxLine = nums[1]
		}
	}

	// 1. Tokenize and filter stop words
	rawTokens := strings.Fields(queryString)
	var tokens []string
	stopWords := map[string]bool{
		"analyse": true, "analyze": true, "the": true, "this": true,
		"log": true, "file": true, "find": true, "show": true,
		"me": true, "about": true, "for": true, "with": true,
		"of": true, "how": true, "msg": true, "flow": true,
		"after": true, "line": true, "between": true, "and": true, // Added for line logic
	}

	for _, token := range rawTokens {
		lowerToken := strings.ToLower(token)
		// Don't add numbers to keyword tokens if we are in "line mode" to avoid filtering on the line number itself in text
		isNumber := false
		var dummy int
		if _, err := fmt.Sscanf(token, "%d", &dummy); err == nil {
			isNumber = true
		}

		if !stopWords[lowerToken] && !((minLine > 0 || maxLine > 0) && isNumber) {
			tokens = append(tokens, lowerToken)
		}
	}

	// If all tokens were stop words (and we have line query), allow empty tokens
	if len(tokens) == 0 && (minLine == -1 && maxLine == -1) {
		tokens = []string{strings.ToLower(queryString)}
	} else if len(tokens) == 0 {
		tokens = []string{} // Valid to have no text tokens if only filtering by line
	}

	return Constraints{
		MinLine:  minLine,
		MaxLine:  maxLine,
		Keywords: tokens,
	}
}

// Execute filters the log entries based on the user query string
// It supports multi-keyword matching (AND logic) and ignores common stop words.
func Execute(entries []parser.LogEntry, queryString string) []parser.LogEntry {
	constraints := ParseConstraints(queryString)
	return ExecuteWithConstraints(entries, constraints)
}

// ExecuteWithConstraints filters entries using pre-parsed constraints
func ExecuteWithConstraints(entries []parser.LogEntry, constraints Constraints) []parser.LogEntry {
	filtered := []parser.LogEntry{}

	for _, entry := range entries {
		// Line Filter Check
		if constraints.MinLine != -1 && entry.Line <= constraints.MinLine {
			continue
		}
		if constraints.MaxLine != -1 && entry.Line >= constraints.MaxLine {
			continue
		}

		matchAll := true
		entryRawLower := strings.ToLower(entry.Raw)

		for _, token := range constraints.Keywords {
			if !strings.Contains(entryRawLower, token) {
				matchAll = false
				break
			}
		}

		if matchAll {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
