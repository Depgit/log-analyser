package query

import (
	"fmt"
	"log-analyser/pkg/parser"
	"strings"
)

// ExprType represents the type of expression node
type ExprType int

const (
	ExprKeyword ExprType = iota
	ExprAND
	ExprOR
)

// Expression represents a logical expression tree
type Expression struct {
	Type    ExprType
	Keyword string      // Used when Type == ExprKeyword
	Left    *Expression // Used when Type == ExprAND or ExprOR
	Right   *Expression // Used when Type == ExprAND or ExprOR
}

// Evaluate checks if the expression matches the given log entry
func (e *Expression) Evaluate(entryRawLower string) bool {
	switch e.Type {
	case ExprKeyword:
		return strings.Contains(entryRawLower, e.Keyword)
	case ExprAND:
		return e.Left.Evaluate(entryRawLower) && e.Right.Evaluate(entryRawLower)
	case ExprOR:
		return e.Left.Evaluate(entryRawLower) || e.Right.Evaluate(entryRawLower)
	}
	return false
}

// Constraints holds the parsed query requirements
type Constraints struct {
	MinLine    int
	MaxLine    int
	Keywords   []string    // For backward compatibility (implicit OR)
	Expression *Expression // For explicit logical operators
}

// ParseConstraints parses the query string to extract line constraints and keywords
func ParseConstraints(queryString string) Constraints {
	if queryString == "" {
		return Constraints{MinLine: -1, MaxLine: -1, Keywords: nil, Expression: nil}
	}

	minLine, maxLine := -1, -1

	// 1. Extract line constraints
	lowerQuery := strings.ToLower(queryString)
	queryRemainder := queryString

	// Simple parsing for "after line <num>"
	if strings.Contains(lowerQuery, "after line") {
		parts := strings.Fields(queryString)
		for i, p := range parts {
			if strings.ToLower(p) == "line" && i+1 < len(parts) {
				// Try parsing next word as number
				var num int
				if _, err := fmt.Sscanf(parts[i+1], "%d", &num); err == nil {
					minLine = num
					// Remove "after line X" from query remainder
					if i+2 < len(parts) {
						queryRemainder = strings.Join(parts[i+2:], " ")
					} else {
						queryRemainder = ""
					}
				}
			}
		}
	} else if strings.Contains(lowerQuery, "between line") {
		// "between line <X> and <Y>"
		parts := strings.Fields(queryString)
		nums := []int{}
		lastNumIdx := -1
		for idx, p := range parts {
			var num int
			if _, err := fmt.Sscanf(p, "%d", &num); err == nil {
				nums = append(nums, num)
				lastNumIdx = idx
			}
		}
		if len(nums) >= 2 {
			minLine = nums[0]
			maxLine = nums[1]
			// Remove "between line X and Y" from query remainder
			if lastNumIdx+1 < len(parts) {
				queryRemainder = strings.Join(parts[lastNumIdx+1:], " ")
			} else {
				queryRemainder = ""
			}
		}
	}

	// 2. Check if query contains explicit operators
	hasOperators := strings.Contains(queryRemainder, "&&") || strings.Contains(queryRemainder, "||")

	if hasOperators {
		// Parse expression with operators
		expr := parseExpression(queryRemainder)
		return Constraints{
			MinLine:    minLine,
			MaxLine:    maxLine,
			Keywords:   nil,
			Expression: expr,
		}
	}

	// 3. Fall back to implicit OR logic (backward compatibility)
	rawTokens := strings.Fields(queryRemainder)
	var tokens []string
	stopWords := map[string]bool{
		"analyse": true, "analyze": true, "the": true, "this": true,
		"log": true, "file": true, "find": true, "show": true,
		"me": true, "about": true, "for": true, "with": true,
		"of": true, "how": true, "msg": true, "flow": true,
	}

	for _, token := range rawTokens {
		lowerToken := strings.ToLower(token)
		if !stopWords[lowerToken] {
			tokens = append(tokens, lowerToken)
		}
	}

	// If all tokens were stop words, allow empty tokens
	if len(tokens) == 0 && queryRemainder != "" {
		tokens = []string{strings.ToLower(queryRemainder)}
	}

	return Constraints{
		MinLine:    minLine,
		MaxLine:    maxLine,
		Keywords:   tokens,
		Expression: nil,
	}
}

// parseExpression parses a query string with && and || operators into an expression tree
// Operator precedence: && has higher precedence than ||
func parseExpression(query string) *Expression {
	// First, split by || (lower precedence)
	orParts := splitByOperator(query, "||")
	if len(orParts) > 1 {
		// Build OR expression tree
		left := parseExpression(strings.TrimSpace(orParts[0]))
		for i := 1; i < len(orParts); i++ {
			right := parseExpression(strings.TrimSpace(orParts[i]))
			left = &Expression{
				Type:  ExprOR,
				Left:  left,
				Right: right,
			}
		}
		return left
	}

	// Then, split by && (higher precedence)
	andParts := splitByOperator(query, "&&")
	if len(andParts) > 1 {
		// Build AND expression tree
		left := parseExpression(strings.TrimSpace(andParts[0]))
		for i := 1; i < len(andParts); i++ {
			right := parseExpression(strings.TrimSpace(andParts[i]))
			left = &Expression{
				Type:  ExprAND,
				Left:  left,
				Right: right,
			}
		}
		return left
	}

	// No operators, this is a keyword
	keyword := strings.ToLower(strings.TrimSpace(query))
	return &Expression{
		Type:    ExprKeyword,
		Keyword: keyword,
	}
}

// splitByOperator splits a string by the given operator, respecting nesting
func splitByOperator(s string, operator string) []string {
	var parts []string
	current := ""
	i := 0

	for i < len(s) {
		if i+len(operator) <= len(s) && s[i:i+len(operator)] == operator {
			parts = append(parts, current)
			current = ""
			i += len(operator)
		} else {
			current += string(s[i])
			i++
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	if len(parts) == 0 {
		return []string{s}
	}

	return parts
}

// Execute filters the log entries based on the user query string
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

		entryRawLower := strings.ToLower(entry.Raw)
		matchFound := false

		// Check if we have an expression tree (explicit operators)
		if constraints.Expression != nil {
			matchFound = constraints.Expression.Evaluate(entryRawLower)
		} else {
			// Fall back to implicit OR logic for keywords
			matchFound = len(constraints.Keywords) == 0 // If no keywords, match all

			for _, token := range constraints.Keywords {
				if strings.Contains(entryRawLower, token) {
					matchFound = true
					break // Found a match, no need to check other keywords
				}
			}
		}

		if matchFound {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
