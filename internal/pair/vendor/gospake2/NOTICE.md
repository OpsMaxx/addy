# gospake2, vendored

Upstream: `salsa.debian.org/vasudev/gospake2`
Version: `v0.0.0-20210510093858-d91629950ad1` (2021-05-10)
Retrieved: 2026-09-17

`UPSTREAM.sha256` records the hash of every file as it was fetched, so a future
reader can tell what we changed from what upstream shipped.

## Why this is vendored rather than pinned

`DESIGN.md` is explicit: vendored, not merely pinned, and reviewed as our own
code. Three reasons, and each one alone would be enough:

1. **It is the most security-critical primitive in the system.** SPAKE2 is what
   stops the relay brute-forcing a 22-bit pairing code. If it is subtly wrong,
   the pairing flow still works and the property it exists to provide is gone,
   with no symptom.
2. **It is unmaintained.** The last release is 2021. SPAKE2 is a finished spec
   rather than a moving target, so that is survivable — but it means nobody
   upstream is going to notice a bug for us.
3. **It lives on a single non-GitHub host.** The same reasoning that rejected
   `tyler-smith/go-bip39` — a repository that vanished, leaving builds working
   only because the module proxy is immutable — applies here with more force. It
   cannot be applied to one and waived for the other.

## Licence: dual, and we elect MIT

**This is dual-licensed: MIT *or* GPL-3.0-or-later, at the recipient's option.**
Upstream's README says so, and the `LICENSE` file contains both texts.

**addy elects the MIT option**, which is what makes it usable here: addy is MIT
and does not take GPL, AGPL, LGPL or SSPL dependencies.

This needs recording rather than assuming, for two reasons. A licence scanner
that string-matches will find "GNU General Public License" in `LICENSE` and flag
this, and the answer is "dual-licensed, MIT elected" rather than a bug. And the
election is a choice we made, so it belongs in writing next to the code rather
than in somebody's memory.

`LICENSE` is kept verbatim, both halves, because the MIT terms require the
copyright notice and permission notice to travel with the software.

## A bug, found by running its own tests

**`TestIntegerGroupSPAKE2` fails about 3% of the time**, reproducibly:

    cd /Users/zeeshan/addy
    go test -count=200 -run TestIntegerGroupSPAKE2 ./internal/pair/vendor/gospake2/

It reports "Element is not in the right group" and one side derives an empty
session key. Six failures in two hundred runs.

It is in the **integer group** (`integergroup/`, the finite-field variant),
which addy does not use. The ed25519 path passed 1,200 consecutive runs of
`TestAsymmetric`, `TestSymmetric` and `TestTranscript`.

That is reassuring and it is not a clean bill of health, for a reason worth
stating: the ed25519 tests passing 1,200 times shows that path is not failing
*in the way the integer group fails*. It does not show the same class of bug --
an element encoding or a missing subgroup check -- is absent there, only that
its tests do not catch one. A probabilistic bug in a PAKE is the shape of thing
that is invisible until it is exploited.

So this is recorded as what it is: a live correctness bug in an unmaintained
library, in a path we do not use, found by the first thing anyone did with the
vendored copy.

## What still has to happen

Reviewing this as our own code is not done by vendoring it. `ed25519group/` is a
hand-written curve implementation — not `crypto/ed25519`, not `filippo.io/edwards25519`
— which is 1,777 lines of arithmetic that has to be right. That review is
tracked separately and must complete before any pairing code ships.

## Local changes

Anything we change goes here with its reason, so the diff against
`UPSTREAM.sha256` is always explained.

- **Not vendored at all:** `cmd/` (an interop test harness), `scripts/`,
  `.gitlab-ci.yml`, `Makefile`. None of it is library code.
- Nothing else yet. **No pairing code ships until the review above completes.**
