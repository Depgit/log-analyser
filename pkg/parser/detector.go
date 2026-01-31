package parser

import (
	"bufio"
	"os"
	"strings"
	"time"
)

type LogType string

const (
	LogTypeUnknown LogType = "UNKNOWN"
	LogTypeSimple  LogType = "SIMPLE" // Date + Level + Msg
	LogTypeJSON    LogType = "JSON"
)

type LogEntry struct {
	Line      int
	Timestamp time.Time
	Level     string
	Message   string
	Raw       string
}

// DetectFormat analyzes the first few lines of the file to determine the format
func DetectFormat(filePath string) (LogType, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return LogTypeUnknown, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	linesChecked := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		if strings.HasPrefix(strings.TrimSpace(line), "{") && strings.HasSuffix(strings.TrimSpace(line), "}") {
			return LogTypeJSON, nil
		}

		// Heuristic for simple logs: Check if it starts with a year (20XX)
		if len(line) > 4 && (strings.HasPrefix(line, "20") || strings.HasPrefix(line, "19")) {
			return LogTypeSimple, nil
		}

		linesChecked++
		if linesChecked > 5 {
			break
		}
	}

	return LogTypeUnknown, nil
}
