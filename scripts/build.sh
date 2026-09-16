#!/usr/bin/env bash
#
# Cross-compile addy for every target we publish, into dist/.
#
# WHAT BREAKS IF CI SKIPS THIS: the release workflow uploads whatever is in
# dist/ and writes a SHA-256 table into the release notes from it. A target that
# silently failed to build does not produce an error at publish time -- it
# produces a release that is missing a platform, with a checksum table that
# looks complete because it only lists what was there. So this script fails the
# whole run on the first target that does not build, and refuses to finish if it
# produced fewer binaries than it has targets.
#
# CGO_ENABLED=0 is load-bearing, not a preference. It is what makes this a loop
# in a shell script instead of six C toolchains, and it is why the pure-Go
# SQLite driver was chosen over the faster cgo one. Nothing here may introduce a
# dependency that needs cgo without also answering how the other five targets
# get built.
#
# -trimpath and an empty -buildid are what make the recorded SHA-256 mean
# anything: without them the hash changes with the checkout path and the build
# machine, and a checksum nobody can reproduce is decoration.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist"

VERSION="${ADDY_VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo '0.0.0-dev')}"
BUILD_SHA="${ADDY_SHA:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)}"

# addy is a server first and a development tool second, so Linux is the point
# and the rest are for running it on a laptop while working on it. Windows is
# included because `addy serve -dev` is how a contributor tries the thing, and
# refusing to build for their machine is a poor answer to that.
TARGETS=(
  "linux   amd64"
  "linux   arm64"
  "darwin  amd64"
  "darwin  arm64"
  "windows amd64"
)

single="${1:-}"

command -v go >/dev/null || { echo "build.sh: go is not on PATH" >&2; exit 1; }

echo "addy $VERSION ($BUILD_SHA)"

# Vet and test BEFORE building anything. A red test should fail the run rather
# than produce an artifact nobody checked -- the same order the sibling repo's
# sidecar build uses, for the same reason.
( cd "$ROOT" && go vet ./... && go test ./... )

rm -rf "$OUT"
mkdir -p "$OUT"

built=0
for entry in "${TARGETS[@]}"; do
  read -r goos goarch <<<"$entry"
  name="${goos}-${goarch}"
  if [ -n "$single" ] && [ "$single" != "$name" ]; then
    continue
  fi

  exe=""
  [ "$goos" = "windows" ] && exe=".exe"
  dest="$OUT/addy_${VERSION}_${goos}_${goarch}${exe}"

  echo "  building $name"
  ( cd "$ROOT" && \
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath \
      -ldflags "-s -w -buildid= -X main.Version=$VERSION -X main.BuildSha=$BUILD_SHA" \
      -o "$dest" ./cmd/addy )
  built=$((built + 1))
done

if [ -n "$single" ] && [ "$built" -eq 0 ]; then
  echo "build.sh: no target matches '$single'" >&2
  printf '  %s\n' "${TARGETS[@]}" >&2
  exit 2
fi
if [ -z "$single" ] && [ "$built" -ne "${#TARGETS[@]}" ]; then
  echo "build.sh: built $built of ${#TARGETS[@]} targets" >&2
  exit 1
fi

# The checksum file is generated here rather than in the release workflow so
# that `bash scripts/build.sh` locally produces byte-identical output to CI,
# which is the only way anyone ever verifies a reproducible build claim.
( cd "$OUT" && find . -type f ! -name 'SHA256SUMS' -print0 \
    | sort -z \
    | xargs -0 shasum -a 256 \
    | sed 's|\./||' > SHA256SUMS )

echo
cat "$OUT/SHA256SUMS"

# Prove the binary for THIS machine actually runs. A cross-compiled artifact
# that cannot execute is caught here rather than by the first person to download
# it, and `version` is the one subcommand that needs no configuration.
host="$OUT/addy_${VERSION}_$(go env GOOS)_$(go env GOARCH)"
[ "$(go env GOOS)" = "windows" ] && host="$host.exe"
if [ -x "$host" ]; then
  echo
  echo -n "smoke: "
  "$host" version
fi
