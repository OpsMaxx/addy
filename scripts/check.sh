#!/usr/bin/env bash
#
# The gate CI runs, runnable locally as one command.
#
# WHAT BREAKS IF YOU HAND-ASSEMBLE THIS INSTEAD: `set -e` does NOT abort on a
# failure inside an `&&` chain, because the chain is a compound condition. So
# `go vet ./... && go test ./...` typed at a prompt reports the vet failure,
# keeps going, and the next command runs anyway -- which is how a commit lands
# with vet red. Each step here is its own statement, so a failure stops the run.
#
# Vendored third-party code is excluded from formatting and vet: it stays
# byte-identical to upstream, which is what makes its recorded hashes mean
# anything. Its TESTS still run, because the design says to review it as our own
# code and running what it ships is the first part of that.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

own_go_files() { git ls-files '*.go' | grep -v '/vendor/'; }
own_packages() { go list ./... | grep -v '/vendor/'; }

echo "==> gofmt"
unformatted="$(gofmt -l $(own_go_files))"
if [ -n "$unformatted" ]; then
  echo "gofmt would change these files:" >&2
  echo "$unformatted" >&2
  exit 1
fi

echo "==> go vet"
go vet $(own_packages)

echo "==> go test"
go test ./...

echo
echo "all green"
