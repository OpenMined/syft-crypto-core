# syft-crypto-core justfile
# Minimal essential commands for development

_default:
    @just --list

# Build entire workspace
build:
    cargo build --workspace

# Build only protocol library
build-protocol:
    cargo build -p syft-crypto-protocol

# Build only CLI
build-cli:
    cargo build -p syft-crypto-cli

# Build release version
build-release:
    cargo build --workspace --release

# Run all tests (24 tests)
test:
    cargo test --workspace

# Run protocol tests only
test-protocol:
    cargo test -p syft-crypto-protocol

# Run with verbose output
test-verbose:
    cargo test --workspace -- --nocapture

# Format code
format:
    cargo fmt --all

# Check formatting without making changes
format-check:
    cargo fmt --all -- --check

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets

# Run clippy with automatic fixes
lint-fix:
    cargo clippy --workspace --all-targets --fix --allow-dirty --allow-staged

# Run all pre-commit checks (format, lint, test)
pre-commit: format lint test

# Clean build artifacts
clean:
    cargo clean

# Generate documentation
doc:
    cargo doc --workspace --no-deps --open

# Run the CLI tool
run *ARGS:
    cargo run -p syft-crypto-cli -- {{ARGS}}

# Show help for CLI commands
cli-help:
    cargo run -p syft-crypto-cli -- --help

# Show help for keygen command
keygen-help:
    cargo run -p syft-crypto-cli -- keygen --help

# Show project structure
tree:
    tree -L 3 -I target

# Show dependency tree
deps:
    cargo tree
