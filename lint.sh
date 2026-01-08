#!/usr/bin/env bash
# lint.sh - Auto-fix Python bindings (parallel, quiet on success)
# Usage: ./lint.sh [--check] [--test]
#   --check  Read-only mode for CI (no auto-fix)
#   --test   Also run tests (slower)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

CHECK_MODE=0
RUN_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_MODE=1 ;;
    --test) RUN_TESTS=1 ;;
  esac
done

BINDINGS="$ROOT_DIR/bindings/python"
PY_SRC="$BINDINGS/python"
YELLOW='\033[0;33m'

# Check if submodules are initialized
if [[ ! -d "$ROOT_DIR/vendor/libsignal-protocol-syft/crates" ]]; then
  echo -e "${YELLOW}⊘ skipped (submodules not initialized)${NC}"
  exit 0
fi

# Setup venv (must be sequential)
export UV_VENV_CLEAR=1
uv venv > /dev/null 2>&1
uv pip install maturin ruff mypy vulture pytest > /dev/null 2>&1

echo -e "${CYAN}→ maturin develop${NC}"
if ! uv run -- maturin develop --manifest-path "$BINDINGS/Cargo.toml" > /dev/null 2>&1; then
  echo -e "${RED}✗ maturin develop failed${NC}"
  exit 1
fi

TMPDIR_LINT=$(mktemp -d)
trap "rm -rf $TMPDIR_LINT" EXIT

FAILED=0
PIDS=()
TASKS=()

run_task() {
  local name="$1"
  local outfile="$TMPDIR_LINT/$name.out"
  shift
  TASKS+=("$name")
  echo -e "${CYAN}→ $name${NC}"
  (
    if "$@" > "$outfile" 2>&1; then
      echo "0" > "$outfile.status"
    else
      echo "1" > "$outfile.status"
    fi
  ) &
  PIDS+=($!)
}

wait_all() {
  local i=0
  for pid in "${PIDS[@]}"; do
    wait "$pid" || true
    local name="${TASKS[$i]}"
    local outfile="$TMPDIR_LINT/$name.out"
    if [[ -f "$outfile.status" && "$(cat "$outfile.status")" != "0" ]]; then
      echo -e "${RED}✗ $name${NC}"
      cat "$outfile"
      echo ""
      FAILED=1
    fi
    i=$((i + 1))
  done
}

if [[ "$CHECK_MODE" -eq 1 ]]; then
  run_task "ruff-format" uv run ruff format "$PY_SRC" --check
  run_task "ruff-check" uv run ruff check "$PY_SRC"
else
  run_task "ruff-format" uv run ruff format "$PY_SRC"
  run_task "ruff-check" uv run ruff check "$PY_SRC" --fix
fi

run_task "mypy" uv run mypy "$PY_SRC"
run_task "vulture" uv run vulture "$PY_SRC" --min-confidence 80

if [[ "$RUN_TESTS" -eq 1 ]]; then
  run_task "pytest" uv run pytest
fi

wait_all

if [[ "$FAILED" -eq 0 ]]; then
  echo -e "${GREEN}✓ All checks passed${NC}"
else
  exit 1
fi
