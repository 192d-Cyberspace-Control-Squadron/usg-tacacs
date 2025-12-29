#!/usr/bin/env bash
set -euo pipefail

# Build with locked dependencies for reproducibility
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR%/scripts}"
cd "$REPO_ROOT"

cargo build --locked "$@"
