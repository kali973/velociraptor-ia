.PHONY: build run test clean tidy

PROJECT_ROOT := $(shell pwd)
BIN_DIR      := bin
BIN_NAME     := velociraptor

# ─── Build ────────────────────────────────────────────────────────────────────
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN_DIR)/$(BIN_NAME) ./cmd
	@echo "✅ Compilé → $(BIN_DIR)/$(BIN_NAME)"

# ─── Run (mode UI) ────────────────────────────────────────────────────────────
run:
	go run ./cmd -ui

# ─── Tests ────────────────────────────────────────────────────────────────────
test:
	go test ./... -count=1

# ─── Hygiène ──────────────────────────────────────────────────────────────────
tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR) logs/

# ─── Notes ────────────────────────────────
# Cibles standard : build, run, test, tidy, clean
