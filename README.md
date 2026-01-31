# `deplog`

A powerful, cross-platform CLI tool for analyzing and querying log files. It automatically detects log formats and supports natural language queries with advanced filtering capabilities.

## Features

- **Format Detection**: Automatically identifies `JSON` and `SIMPLE` (timestamped) log formats.
- **Smart Querying**: specific Support for natural language queries (e.g., "analyse the IMSI 12345"). It filters out stop words and combines key terms.
- **Line Filtering**: Filter logs by specific line numbers or ranges (e.g., "after line 50", "between line 10 and 20").
- **Dynamic Reporting**: Generates concise reports based on your queries.
- **Cross-Platform**: Runs on Linux, Windows, and macOS.

## Installation

### Build from Source
Prerequisites: Go 1.25+

```bash
# Build for your current OS
make build
# Creates ./deplog binary
```

### Cross-Correction Build
To build for all supported platforms (Linux, Windows, Mac):

```bash
make release
# Binaries will be generated in the bin/ directory
```

## Usage

Run the tool by providing the log file and an optional query.

```bash
./deplog <logfile> [query]
```

### Examples

**1. Analyze a file (Default report)**
```bash
./deplog sample.log
```

**2. Filter by text (Smart Query)**
FIND lines containing "ERROR" or "connection":
```bash
./deplog sample.log "analyse errors with connection"
```

**3. Filter by Line Number**
Read logs after line 100:
```bash
./deplog sample.log "after line 100"
```

Read logs between lines 50 and 60:
```bash
./deplog sample.log "between line 50 and 60"
```

**4. Combine Filters**
Find "INFO" logs starting after line 5:
```bash
./deplog sample.log "after line 5 analyse INFO"
```

## Project Structure

- `cmd/log-analyser`: Main entry point.
- `pkg/parser`: Log format detection and parsing logic.
- `pkg/query`: Advanced query engine with tokenization and line filtering.
- `pkg/report`: Report generation.
- `Makefile`: Build and release automation.
