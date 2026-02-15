package query

import (
	"fmt"
	"log-analyser/pkg/parser"
	"regexp"
	"strings"
	"text/scanner"
)

// ExprType represents the type of expression node
type ExprType int

const (
	ExprKeyword ExprType = iota
	ExprAND
	ExprOR
	ExprNOT
)

// Expression represents a logical expression tree
type Expression struct {
	Type    ExprType
	Keyword string         // Used when Type == ExprKeyword
	Regex   *regexp.Regexp // Pre-compiled regex if RegexMode or GlobMode is on
	Left    *Expression    // Used when Type == ExprAND or ExprOR
	Right   *Expression    // Used when Type == ExprAND or ExprOR
	Child   *Expression    // Used when Type == ExprNOT
}

// Evaluate checks if the expression matches the given log entry
func (e *Expression) Evaluate(entryRaw string, constraints Constraints) bool {
	if e == nil {
		return false
	}
	switch e.Type {
	case ExprKeyword:
		if constraints.Regex || constraints.Glob {
			if e.Regex == nil {
				// Fallback if not pre-compiled (should not happen with new error handling)
				pattern := e.Keyword
				if constraints.Glob {
					pattern = globToRegex(pattern)
				}
				if !constraints.CaseSensitive {
					pattern = "(?i)" + pattern
				}
				matched, _ := regexp.MatchString(pattern, entryRaw)
				return matched
			}
			return e.Regex.MatchString(entryRaw)
		}

		haystack := entryRaw
		needle := e.Keyword
		if !constraints.CaseSensitive {
			haystack = strings.ToLower(entryRaw)
			needle = strings.ToLower(e.Keyword)
		}
		return strings.Contains(haystack, needle)

	case ExprAND:
		return e.Left.Evaluate(entryRaw, constraints) && e.Right.Evaluate(entryRaw, constraints)
	case ExprOR:
		return e.Left.Evaluate(entryRaw, constraints) || e.Right.Evaluate(entryRaw, constraints)
	case ExprNOT:
		return !e.Child.Evaluate(entryRaw, constraints)
	}
	return false
}

// Constraints holds the parsed query requirements
type Constraints struct {
	MinLine       int
	MaxLine       int
	CaseSensitive bool
	Regex         bool
	Glob          bool
	Expression    *Expression
}

// ParseConstraints parses the query string to extract line constraints and the query expression
func ParseConstraints(queryString string, regexMode bool, globMode bool, caseSensitive bool) (Constraints, error) {
	if queryString == "" {
		return Constraints{MinLine: -1, MaxLine: -1, Regex: regexMode, Glob: globMode, CaseSensitive: caseSensitive, Expression: nil}, nil
	}

	minLine, maxLine := -1, -1
	queryRemainder := queryString

	lowerQuery := strings.ToLower(queryString)
	if strings.Contains(lowerQuery, "after line") {
		parts := strings.Fields(queryString)
		for i, p := range parts {
			if strings.ToLower(p) == "line" && i+1 < len(parts) {
				var num int
				if _, err := fmt.Sscanf(parts[i+1], "%d", &num); err == nil {
					minLine = num
					if i+2 < len(parts) {
						queryRemainder = strings.Join(parts[i+2:], " ")
					} else {
						queryRemainder = ""
					}
				}
			}
		}
	} else if strings.Contains(lowerQuery, "between line") {
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
			if lastNumIdx+1 < len(parts) {
				queryRemainder = strings.Join(parts[lastNumIdx+1:], " ")
			} else {
				queryRemainder = ""
			}
		}
	}

	expr, err := ParseExpression(queryRemainder, regexMode, globMode, caseSensitive)
	if err != nil {
		return Constraints{}, err
	}

	return Constraints{
		MinLine:       minLine,
		MaxLine:       maxLine,
		CaseSensitive: caseSensitive,
		Regex:         regexMode,
		Glob:          globMode,
		Expression:    expr,
	}, nil
}

// Lexer and Parser

type TokenType int

const (
	TokenError TokenType = iota
	TokenEOF
	TokenIdentifier
	TokenString
	TokenAND
	TokenOR
	TokenNOT
	TokenLParen
	TokenRParen
)

type Token struct {
	Type  TokenType
	Value string
}

type Lexer struct {
	s   scanner.Scanner
	buf *Token
}

func NewLexer(input string) *Lexer {
	var s scanner.Scanner
	s.Init(strings.NewReader(input))
	// Support more characters in identifiers for regex and unquoted phrases
	s.IsIdentRune = func(ch rune, i int) bool {
		if ch == '&' || ch == '|' || ch == '!' || ch == '(' || ch == ')' || ch == '"' {
			return false
		}
		return ch > 32 && ch < 127 // Any printable non-operator char
	}
	s.Mode = scanner.ScanIdents | scanner.ScanStrings
	s.Error = func(s *scanner.Scanner, msg string) {}
	return &Lexer{s: s}
}

func (l *Lexer) Peek() Token {
	if l.buf != nil {
		return *l.buf
	}
	tok := l.Next()
	l.buf = &tok
	return tok
}

func (l *Lexer) Next() Token {
	if l.buf != nil {
		t := *l.buf
		l.buf = nil
		return t
	}

	tok := l.s.Scan()
	if tok == scanner.EOF {
		return Token{Type: TokenEOF}
	}

	text := l.s.TokenText()

	switch tok {
	case scanner.String:
		return Token{Type: TokenString, Value: strings.Trim(text, "\"")}
	case '(':
		return Token{Type: TokenLParen, Value: "("}
	case ')':
		return Token{Type: TokenRParen, Value: ")"}
	case '!':
		return Token{Type: TokenNOT, Value: "!"}
	case '&':
		if l.s.Peek() == '&' {
			l.s.Scan()
			return Token{Type: TokenAND, Value: "&&"}
		}
		return Token{Type: TokenAND, Value: "&&"}
	case '|':
		if l.s.Peek() == '|' {
			l.s.Scan()
			return Token{Type: TokenOR, Value: "||"}
		}
		return Token{Type: TokenOR, Value: "||"}
	}

	upper := strings.ToUpper(text)
	if upper == "AND" {
		return Token{Type: TokenAND, Value: "&&"}
	}
	if upper == "OR" {
		return Token{Type: TokenOR, Value: "||"}
	}
	if upper == "NOT" {
		return Token{Type: TokenNOT, Value: "!"}
	}

	return Token{Type: TokenIdentifier, Value: text}
}

type Parser struct {
	lexer *Lexer
}

func ParseExpression(input string, regexMode bool, globMode bool, caseSensitive bool) (*Expression, error) {
	p := &Parser{lexer: NewLexer(input)}
	expr := p.parseOr()

	if regexMode || globMode {
		if err := compileRegex(expr, regexMode, globMode, caseSensitive); err != nil {
			return nil, err
		}
	}
	return expr, nil
}

func compileRegex(e *Expression, regexMode bool, globMode bool, caseSensitive bool) error {
	if e == nil {
		return nil
	}
	if e.Type == ExprKeyword {
		pattern := e.Keyword
		if globMode {
			pattern = globToRegex(pattern)
		}
		if !caseSensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid pattern %q: %v", e.Keyword, err)
		}
		e.Regex = re
	}
	if err := compileRegex(e.Left, regexMode, globMode, caseSensitive); err != nil {
		return err
	}
	if err := compileRegex(e.Right, regexMode, globMode, caseSensitive); err != nil {
		return err
	}
	return compileRegex(e.Child, regexMode, globMode, caseSensitive)
}

func globToRegex(glob string) string {
	var builder strings.Builder
	for i := 0; i < len(glob); i++ {
		ch := glob[i]
		switch ch {
		case '*':
			// Handle multiple * as single .* for simplicity
			for i+1 < len(glob) && glob[i+1] == '*' {
				i++
			}
			builder.WriteString(".*")
		case '?':
			builder.WriteString(".")
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '\\', '|':
			builder.WriteByte('\\')
			builder.WriteByte(ch)
		default:
			builder.WriteByte(ch)
		}
	}
	return builder.String()
}

func (p *Parser) parseOr() *Expression {
	left := p.parseAnd()
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenOR {
			p.lexer.Next()
			right := p.parseAnd()
			left = &Expression{Type: ExprOR, Left: left, Right: right}
		} else {
			break
		}
	}
	return left
}

func (p *Parser) parseAnd() *Expression {
	left := p.parseFactor()
	for {
		tok := p.lexer.Peek()
		if tok.Type == TokenAND {
			p.lexer.Next()
			right := p.parseFactor()
			left = &Expression{Type: ExprAND, Left: left, Right: right}
		} else {
			if tok.Type == TokenIdentifier || tok.Type == TokenString || tok.Type == TokenNOT || tok.Type == TokenLParen {
				right := p.parseFactor()
				left = &Expression{Type: ExprAND, Left: left, Right: right}
			} else {
				break
			}
		}
	}
	return left
}

func (p *Parser) parseFactor() *Expression {
	tok := p.lexer.Peek()

	switch tok.Type {
	case TokenNOT:
		p.lexer.Next()
		child := p.parseFactor()
		return &Expression{Type: ExprNOT, Child: child}
	case TokenLParen:
		p.lexer.Next()
		expr := p.parseOr()
		if p.lexer.Peek().Type == TokenRParen {
			p.lexer.Next()
		}
		return expr
	case TokenIdentifier, TokenString:
		p.lexer.Next()
		return &Expression{Type: ExprKeyword, Keyword: tok.Value}
	default:
		if tok.Type == TokenEOF {
			return nil
		}
		p.lexer.Next()
		return nil
	}
}

// Execute filters the log entries based on the user query string
func Execute(entries []parser.LogEntry, queryString string) []parser.LogEntry {
	// Defaults for Execute when called directly
	constraints, _ := ParseConstraints(queryString, false, false, false)
	return ExecuteWithConstraints(entries, constraints)
}

// ExecuteWithConstraints filters entries using pre-parsed constraints
func ExecuteWithConstraints(entries []parser.LogEntry, constraints Constraints) []parser.LogEntry {
	filtered := []parser.LogEntry{}

	for _, entry := range entries {
		if constraints.MinLine != -1 && entry.Line <= constraints.MinLine {
			continue
		}
		if constraints.MaxLine != -1 && entry.Line >= constraints.MaxLine {
			continue
		}

		if constraints.Expression != nil {
			if constraints.Expression.Evaluate(entry.Raw, constraints) {
				filtered = append(filtered, entry)
			}
		} else {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
