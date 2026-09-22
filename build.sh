#!/usr/bin/env bash

# On success this script is silent (no stdout/stderr) and exits 0.
# On failure it prints the failing step's output to stderr and exits non-zero.
set -euo pipefail

# Run a build step silently; on failure, print its combined output to stderr
# and abort with a non-zero exit code.
run() {
  local output
  if ! output=$("$@" 2>&1); then
    printf 'build.sh: step failed: %s\n' "$*" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
}

run cargo build
run cargo test
run cargo clippy
run cargo fmt --check
