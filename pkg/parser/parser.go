package parser

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

func Parse(filePath string, logType LogType, minLine, maxLine int) ([]LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	entries := []LogEntry{}
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++

		// Optimization: Stop reading if we reached the maxLine (exclusive)
		if maxLine != -1 && lineNum >= maxLine {
			break
		}

		// Optimization: Skip lines strict-after check (lineNum <= minLine)
		if minLine != -1 && lineNum <= minLine {
			continue
		}

		line := scanner.Text()
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		entry := LogEntry{Raw: line, Line: lineNum}

		switch logType {
		case LogTypeJSON:
			var jsonMap map[string]interface{}
			if err := json.Unmarshal([]byte(line), &jsonMap); err == nil {
				if val, ok := jsonMap["message"].(string); ok {
					entry.Message = val
				}
				if val, ok := jsonMap["level"].(string); ok {
					entry.Level = val
				}
				// Attempt to parse timestamp if present, otherwise ignore
			}
		case LogTypeSimple:
			// Expected format: 2023-10-27 10:00:01 [INFO] Application started
			parts := strings.SplitN(line, " ", 4)
			if len(parts) >= 4 {
				entry.Level = strings.Trim(parts[2], "[]")
				entry.Message = parts[3]
				// Basic timestamp parse (omitted for brevity, keeping it simple)
			} else {
				entry.Message = line
			}
		default:
			entry.Message = line
		}

		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}
