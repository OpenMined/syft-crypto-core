# List of commands runnable with https://github.com/casey/just
# Run `just --list` to see all available commands
#
# Optional dev tools (install with cargo install):
#   - cargo-watch: for watch/watch-check commands
#   - cargo-audit: for security auditing
#   - cargo-outdated: for checking outdated deps
#   - cargo-machete: for finding unused deps
#   - cargo-tarpaulin: for test coverage

_default:
    @just --list

# Install recommended development tools
install-dev-tools:
    cargo install cargo-watch cargo-audit cargo-outdated cargo-machete cargo-tarpaulin

# Build the project in debug mode
build:
    cargo build

# Build the project in release mode
build-release:
    cargo build --release

# Run all tests
test:
    cargo test --workspace --all-features --verbose -- --nocapture

# Run tests with ignored tests included
test-all:
    cargo test --workspace --all-features --verbose -- --include-ignored

# Run a specific test
test-single TEST:
    cargo test {{TEST}} --verbose -- --nocapture

# Format all Rust code
format:
    cargo fmt

# Check if code is properly formatted without making changes
check-format:
    cargo fmt --all -- --check

# Run clippy linter with strict warnings
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run clippy and attempt to fix issues automatically
lint-fix:
    cargo clippy --fix --workspace --all-targets --all-features --allow-dirty --allow-staged

# Clean build artifacts
clean:
    cargo clean

# Generate documentation
doc:
    cargo doc --no-deps --open

# Generate documentation for all dependencies
doc-all:
    cargo doc --open

# Run benchmarks (if any)
bench:
    cargo bench

# Check for outdated dependencies
outdated:
    cargo outdated

# Update dependencies
update:
    cargo update

# Run security audit on dependencies
audit:
    cargo audit

# Run all checks before committing (format, lint, test)
pre-commit: check-format lint test
    @echo " All pre-commit checks passed!"

# Run extended checks including security audit
check-all: check-format lint test audit
    @echo " All checks passed!"

# Watch for changes and run tests automatically
watch:
    cargo watch -x test

# Watch for changes and run checks automatically
watch-check:
    cargo watch -x check -x test

# Show project dependencies tree
deps:
    cargo tree

# Show reverse dependencies (what depends on a package)
deps-rev PACKAGE:
    cargo tree -i {{PACKAGE}}

# Run the project (if it has a binary)
run:
    cargo run

# Run with release optimizations
run-release:
    cargo run --release

# Install the project locally
install:
    cargo install --path .

# Create a new example
example NAME:
    @mkdir -p examples
    @echo 'fn main() {\n    println!("Example: {{NAME}}");\n}' > examples/{{NAME}}.rs
    @echo "Created examples/{{NAME}}.rs"

# Run a specific example
run-example NAME:
    cargo run --example {{NAME}}

# Check for unused dependencies
unused-deps:
    cargo machete

# Generate test coverage report (requires cargo-tarpaulin)
coverage:
    cargo tarpaulin --out html --output-dir target/coverage

# Package the crate for publishing
package:
    cargo package --allow-dirty

# Publish to crates.io (dry run)
publish-dry:
    cargo publish --dry-run --allow-dirty

# Publish to crates.io
publish:
    cargo publish
