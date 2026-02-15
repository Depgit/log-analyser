package query

import (
	"testing"
)

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		entry       string
		sensitive   bool
		regex       bool
		glob        bool
		shouldMatch bool
	}{
		// Basic keywords
		{"Single keyword match", "error", "This is an error", false, false, false, true},
		{"Case sensitive match", "ERROR", "This is an ERROR", true, false, false, true},
		{"Case sensitive fail", "ERROR", "This is an error", true, false, false, false},

		// Regex
		{"Regex simple", "^error", "error occurred", false, true, false, true},
		{"Regex fail", "^error", "an error", false, true, false, false},
		{"Regex case insensitive", "ERROR", "error", false, true, false, true},
		{"Regex case sensitive", "ERROR", "error", true, true, false, false},

		// Glob
		{"Glob basic", "G*T", "GET", false, false, true, true},
		{"Glob double star", "G**T", "GET", false, false, true, true},
		{"Glob question", "G?T", "GET", false, false, true, true},
		{"Glob middle match", "*test*", "this is a test log", false, false, true, true},
		{"Glob no match", "G?T", "GEET", false, false, true, false},

		// logic (already tested, just verifying signature)
		{"AND sensitive", "ERR && CRIT", "ERR CRIT", true, false, false, true},
		{"AND sensitive fail", "ERR && CRIT", "err crit", true, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraints, err := ParseConstraints(tt.query, tt.regex, tt.glob, tt.sensitive)
			if err != nil {
				t.Fatalf("Failed to parse constraints: %v", err)
			}
			matched := constraints.Expression.Evaluate(tt.entry, constraints)
			if matched != tt.shouldMatch {
				t.Errorf("Query %q on %q (regex=%v, glob=%v, sensitive=%v): expected %v, got %v", tt.query, tt.entry, tt.regex, tt.glob, tt.sensitive, tt.shouldMatch, matched)
			}
		})
	}
}
