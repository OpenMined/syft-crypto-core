# syft-crypto-core

End-to-end encrypted communication and file synchronization for SyftBox using the Signal protocol.

## Overview

This crate provides cryptographic primitives for secure messaging and file synchronization in SyftBox, built on top of [libsignal's implementation](https://github.com/signalapp/libsignal) of the Signal protocol. It includes support for the X3DH key agreement protocol with post-quantum security via Kyber.

## Features


## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
syft-crypto-core = "0.1.0"
```

## Development

```bash
# Install development tools
just install-dev-tools

# Run all tests
just test

# Run all pre-commit checks
just pre-commit

# Format code
just format

# Run linter
just lint
```

## License

Apache-2.0

## Repository

https://github.com/OpenMined/syft-crypto-core
