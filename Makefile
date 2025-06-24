.PHONY: help build run test clean generate lint install dev-setup

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

# Variables
BINARY_NAME=where-am-i
BUILD_DIR=bin
CMD_DIR=cmd/where-am-i
VERSION?=dev
LDFLAGS=-s -w -X main.version=$(VERSION)

build: generate ## Build the application
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go

run: generate ## Run the application
	go run $(CMD_DIR)/main.go $(ARGS)

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)
	rm -f proto/*.pb.go

generate: ## Generate protobuf files
	nix develop -c buf generate

lint: ## Run linter
	golangci-lint run

install: build ## Install the binary to GOPATH/bin
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

dev-setup: ## Set up development environment (requires nix)
	nix develop

# Example usage targets
example-locate: build ## Run example locate command
	./$(BUILD_DIR)/$(BINARY_NAME) locate --help

example-config: ## Show example configuration
	@echo "Example configuration file:"
	@cat config.example.yaml

# Build for multiple platforms
build-all: generate ## Build for multiple platforms
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)/main.go
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)/main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)/main.go
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)/main.go
