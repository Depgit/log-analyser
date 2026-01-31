.PHONY: build run clean install

BINARY_NAME=deplog

build:
	go build -o $(BINARY_NAME) cmd/log-analyser/main.go

run:
	go run cmd/log-analyser/main.go $(ARGS)

clean:
	go clean
	rm -f $(BINARY_NAME)
	rm -rf bin

install:
	go install cmd/log-analyser/main.go

# Cross compilation
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
