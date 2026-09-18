# 0002 — How the client gets the protocol

**Status: accepted, 2026-09-18.**

## The question

`addyd --crypto`, the Go sidecar inside the OpsMaxx client, must produce
byte-identical canonical encodings, signatures, roster hashes and sealed
objects to this server. Two implementations that disagree by one byte do not
fail loudly: they fail as an AEAD error with no diagnostic, or as a roster the
client rejects as a fork.

Three constraints shaped the answer, and each one kills an option.

1. **Go forbids importing another module's `internal/`.**
   `github.com/opsmaxx/addy/internal/protocol` is reachable only from inside
   this module.
2. **This repository is not published yet, and the client's is.** OpsMaxx is a
   public MIT repo whose CI builds its sidecars on GitHub-hosted runners with
   no credentials. A dependency on a repo that is private, or absent, breaks
   `go build` for every external contributor as well as for CI — and it breaks
   it in the one place a contributor cannot fix.
3. **The design refuses a single repository** — different language, release
   cadence and audience (DESIGN.md).

## The decision

**Vendor the package into `sidecar/addyd/protocol/`, and make the shared
contract `testdata/vectors.json` rather than the source.**

The source is a copy. The *contract* is the vector file, and that is the part
that is genuinely shared: `vectorcheck_test.go` in this repo, and the same test
in the sidecar, both assert their implementation reproduces the same fixed
encodings, signatures and chain hashes from the same fixed inputs.

This inverts the usual worry about vendoring. The risk of a copy is that it
drifts, and source comparison is the obvious gate — but source comparison is
also the wrong gate, because identical source was never the requirement.
Identical OUTPUT is. Two implementations can diverge freely in structure and
still be correct; they cannot diverge by one byte of output and be anything.
The vectors test exactly the property that matters and nothing else.

## What this rejects

**Promoting `internal/protocol` to a public `github.com/opsmaxx/addy/protocol`
and importing it.** Cleanest on paper, and it is the thing to do the day this
repo is published *and* the client is willing to take a dependency on it. It
fails constraint 2 today and would keep failing it in spirit afterwards: a
public client repo whose build needs a second repo to resolve is a client repo
that breaks whenever that resolution does.

**A third module both depend on.** Same publication problem, one more repo to
release, and it would still be vendored into the client for the same reason.

**A `replace` directive.** Not viable at all. `replace` with a local path makes
the build depend on a sibling directory existing, so every clone that is not
this developer's machine fails — CI included. It is a tool for working on two
modules at once, not for shipping.

## The gate, and where it runs

`vectors.json` carries `_meta.version` (`addy-protocol-v1`). Both
implementations pin it:

- This repo's `vectorcheck_test.go` asserts the implementation reproduces the
  file, and that the file's version matches the `ProtocolVersion` constant.
- The sidecar's copy of both files does the same, in OpsMaxx's CI, with no
  access to this repo and no network.

So a protocol change here that is not carried across does not silently diverge:
it forces a version bump, and a sidecar still claiming the old version is
refused by this server's version check at connect time — before any object is
sealed, rather than after.

The failure this cannot catch is a change made identically in both copies but
wrongly. Nothing catches that; it is what review is for.

## Licence and branding

The vendored code is ours, MIT, same copyright line. It adds no third-party
obligation and nothing to `THIRD-PARTY-NOTICES.md` in either repo — that file
is generated from what actually linked, and this links nothing new beyond the
two dependencies the sidecar declares for itself.

The client's branding test greps every tracked file for the retired product
name. Vendored code is tracked code, so it is in scope, and it passes for the
ordinary reason: none of it contains the word.

## What changes when this repo is published

Nothing has to. The vendoring is not a workaround waiting to be removed — it is
what keeps the public client repo buildable by anyone who clones it. Publishing
makes option (a) *possible*; it does not make it better.
