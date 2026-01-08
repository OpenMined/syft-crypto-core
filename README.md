# syft-crypto-core

End-to-end encrypted communication and file synchronization for SyftBox using the Signal protocol.

## Overview

This crate provides cryptographic primitives for secure messaging and file synchronization in SyftBox, built on top of [libsignal's implementation](https://github.com/signalapp/libsignal) of the Signal protocol. It includes support for the PQXDH key agreement protocol for post-quantum security via Kyber.

## Status

This software is considered Beta so use at your own risk.

## Project Structure

Following Signal's workspace pattern:

```
syft-crypto-core/
├── protocol/           # Core crypto library (keep as small as possible for easy security audit)
│   ├── src/
│   │   └── lib.rs
│   └── tests/          # Comprehensive tests
│
├── cli/                # Command-line interface to use the API in protocol/
│   └── src/
│       └── main.rs
│
└── Cargo.toml          # Workspace configuration
```

## Development

### Quick Start

```bash
just --list           # Show all commands
just build            # Build workspace
just test             # Run all tests
```

### Build Commands

```bash
just build            # Build entire workspace
just build-protocol   # Build only protocol library
just build-cli        # Build only CLI
just build-release    # Release build
```

### Test Commands

```bash
just test             # Run all tests
just test-protocol    # Protocol tests only
just test-verbose     # Tests with output
```

### Code Quality

```bash
just format           # Format code
just lint             # Run clippy
just pre-commit       # Format + lint + test
```

### CLI Commands

```bash
just run <ARGS>       # Run CLI with arguments
just cli-help         # Show CLI help
just keygen-help      # Show keygen help
```

### Utilities

```bash
just clean            # Clean build artifacts
just doc              # Generate documentation
just tree             # Show project structure
```

## License

Apache-2.0

## Repository

https://github.com/OpenMined/syft-crypto-core
