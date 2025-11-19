#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINDINGS="$ROOT/bindings/python"
PY_SRC="$BINDINGS/python"

export UV_VENV_CLEAR=1
uv venv
uv pip install maturin ruff mypy vulture pytest

echo "Building extension in dev mode..."
uv run -- maturin develop --manifest-path "$BINDINGS/Cargo.toml"

echo "Running ruff format..."
uv run ruff format "$PY_SRC"

echo "Running ruff check with fixes..."
uv run ruff check "$PY_SRC" --fix

echo "Running mypy..."
uv run mypy "$PY_SRC"

echo "Running vulture to detect dead code..."
uv run vulture "$PY_SRC" --min-confidence 80

echo "✓ All linting checks passed!"
