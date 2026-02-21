.PHONY: build run clean install web build-web

BINARY_NAME=deplog
WEB_BINARY=wireshark-analyser

# ── CLI log analyser ───────────────────────────────────────────────
build:
	go build -o $(BINARY_NAME) cmd/log-analyser/main.go

run:
	go run cmd/log-analyser/main.go $(ARGS)

install:
	go install cmd/log-analyser/main.go

# ── Wireshark Web Analyser ─────────────────────────────────────────
# Run dev server (opens on http://localhost:8080)
web:
	go run ./cmd/web-server/

# Build production binary
build-web:
	go build -o bin/$(WEB_BINARY) ./cmd/web-server/

# Cross compile web server
build-web-linux:
	GOOS=linux GOARCH=amd64 go build -o bin/$(WEB_BINARY)-linux-amd64 ./cmd/web-server/

build-web-mac:
	GOOS=darwin GOARCH=amd64 go build -o bin/$(WEB_BINARY)-darwin-amd64 ./cmd/web-server/
	GOOS=darwin GOARCH=arm64 go build -o bin/$(WEB_BINARY)-darwin-arm64 ./cmd/web-server/

# ── Common ────────────────────────────────────────────────────────
clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -rf bin

# Cross compile CLI
DIST_DIR=bin

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 cmd/log-analyser/main.go

build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe cmd/log-analyser/main.go

build-mac:
	GOOS=darwin GOARCH=amd64 go build -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 cmd/log-analyser/main.go
	GOOS=darwin GOARCH=arm64 go build -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 cmd/log-analyser/main.go

release: clean build-linux build-windows build-mac
	@echo "Build complete. Binaries are in $(DIST_DIR)/"
