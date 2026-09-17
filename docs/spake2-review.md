# Security review: vendored gospake2

Reviewed: 2026-09-17. Subject: `internal/pair/vendor/gospake2/`, upstream
`salsa.debian.org/vasudev/gospake2` v0.0.0-20210510093858-d91629950ad1.

This is the review `NOTICE.md` says must complete before any pairing code ships.
It is written against the code, not the README — every claim below has a
`file:line` and, where it is a behavioural claim, a measurement.

Nothing in the vendored tree was modified. Probe tests were written, run, and
deleted; `shasum -a 256` over the tree still matches `UPSTREAM.sha256`.

---

## Verdict: DO NOT USE

Not "safe after fixes". Findings 2–5 are all fixable with enough work. **Finding
1 is not**, because it is not a bug in the code — it is a question about where
four numbers came from, and the answer is unavailable.

| # | Finding | Severity | Evidence |
|---|---|---|---|
| 1 | M and N are not the standard constants and have no derivation — the nothing-up-my-sleeve property is absent | Critical | `ed25519group/ed25519.go:32-56` |
| 2 | Remote unauthenticated panic on 7 of 8 hostile frames | Critical | `gospake2.go:339`, `ed25519group/extended.go:38-40` |
| 3 | Variable-time scalar multiplication on the password scalar | Critical | `ed25519group/extended.go:295-319` |
| 4 | Variable-length element encoding — the 3% integer-group bug, also present in the ed25519 path | High | `integergroup/integergroup.go:60`, `ed25519group/affine.go:110`, `gospake2.go:205` |
| 5 | No length, canonicality or side-byte validation; `Decompress` error discarded | High | `ed25519group/ed25519.go:132-134`, `ed25519group/affine.go:117`, `spakeerror.go:9,12` |

Deleting `integergroup/` does not rescue this. The path addy would actually use
carries the same encoding bug, crashes on adversarial input, leaks the password
through timing, and rests on constants nobody can vouch for.

**Alternative: write the SPAKE2 layer on `filippo.io/edwards25519`, following
RFC 9382.** See "Alternative" at the end.

---

## 1. The integer-group bug

### Root cause

Neither group encodes elements to a fixed width, and `Start` pads at the wrong
end. Three lines in three files:

- `integergroup/integergroup.go:60` — `return element.e.Bytes()`.
  `big.Int.Bytes()` is **big-endian, minimal-length**: leading zero bytes are
  dropped.
- `gospake2.go:205-207` — `make([]byte, ElementSize()+1)` then
  `copy(messageAndSide[1:], m1Bytes)`. The frame is fixed-width and the element
  is copied **left-aligned**, so a short encoding leaves the zero fill **on the
  right**.
- `integergroup/integergroup.go:69` — the receiver requires
  `len(b) == grp.elementSizeBytes`, so the malformed frame passes the length
  check. `x.SetBytes(b)` then reads it as `e · 256^k`, and the subgroup test at
  `:82` fails with `"Element is not in the right group"`.

It is leading-zero truncation, not a missing or incorrect subgroup check.

### Confirmation

A probe correlating short encodings against `Finish` failures, over 9,000
handshakes across all three integer groups, written to `t.Fatalf` on any
disagreement in either direction:

```
iterations=9000  shortEncoding=107 (1.19%)  finishFailed=107  both=107
```

Perfect correlation, no mismatches. 1.19% per group × 3 groups per test run
≈ 3.5%, which is the observed ~3% failure rate of `TestIntegerGroupSPAKE2`.

### The same class of bug IS in the ed25519 path

Not "could be". `ed25519group/affine.go:110-112` has the identical defect —
`result.Bytes()` then `reverse(...)`, minimal-length again:

```
ed25519 Start(): 38/12000 = 0.317% of outbound elements encode to FEWER than 32 bytes
```

It does not *manifest*, for two reasons that are both coincidences rather than
correctness:

1. **Endianness.** The ed25519 encoding is little-endian, so the missing
   high-order byte belongs at index 31 — exactly where `Start`'s right-hand zero
   fill lands. The integer group's encoding is big-endian, so its missing byte
   belongs at index 0 and the fill lands at the wrong end. Same bug, opposite
   outcome, purely because of byte order.
2. **The ed25519 receiver is *less* validating than the one that fails.**
   `ed25519group/ed25519.go:132` has **no length check at all** — the check that
   makes `integergroup` fail loudly at `:69` does not exist on the path addy
   would use. The short frame is silently accepted.

6,000 ed25519 handshakes agreed on the key every time, including the
short-encoding runs. That is the 1,200/1,200 result, extended, and it is not
reassurance: a latent encoding bug is being masked by a byte-order accident and
a missing input check.

One thing the mask does not cover: `gospake2.go:347`,
`bytes.Equal(s.message, inbound)`. `s.message` holds the short local encoding
while `inbound` is the zero-padded 32 bytes off the wire, so **the
anti-reflection check fails open in the ~0.3% of sessions where the local
encoding is short.**

---

## 2. `ed25519group/` reviewed as our own code

### 2a. M and N are not the standard constants

`ed25519group/ed25519.go:32-70` hardcodes M, N and S as four raw extended
coordinates each, with a comment claiming they came from `python-spake2`'s
`ParamsEd25519`. They did not. Compressed with the library's own encoder:

```
vendored M = 15cfd18e385952982b6a8f8c7854963b58e34388c8e6dae891db756481a02312
RFC 9382 M = d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf   MATCH=false

vendored N = f04f2e7eb734b2a8f8b472eaf9c3c632576ac64aea650b496a8a20ff00e583c3
RFC 9382 N = d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab   MATCH=false
```

This is not an artifact of the comparison method. The same encoder produces
`5866...6666` for the base point (correct), and it round-trips the *standard* M
and N byte-for-byte through `ElementFromBytes`/`ElementToBytes`. The encoder is
fine. **The constants are different points.**

They are real points — on-curve, in the prime-order subgroup, self-round-tripping.
Checked and ruled out: `k·M_std` for k ∈ 2..8, `−M_std`, M/N swapped, and any
discrete log to B under 4096. No derivation was found.

**Why this decides the verdict.** SPAKE2's security rests entirely on nobody
knowing `log_B(M)` and `log_B(N)`. The standard values earn that by being the
published output of a fixed, reproducible derivation that anyone can recompute.
These are four unexplained integers in a source file. Their discrete logs cannot
be shown to be known; that is not the point. **They cannot be shown to be
unknown**, and that is precisely the assumption addy is buying SPAKE2 to rely
on. If whoever produced them knows `log_B(M)`, an active attacker on the relay
recovers the pairing code offline from a single session, the flow still
completes, and there is no symptom — the exact failure mode `NOTICE.md` names.

Two corollaries:

- **Nothing in the test suite would ever catch this.**
  `ed25519group/const_test.go` covers Q, L, D, I and the base point, and has **no
  test for M, N or S at all**. `gospake2_test.go`'s transcript tests hash the
  library's own output against itself. There is not one cross-implementation
  known-answer vector anywhere in the suite.
- **`DESIGN.md` says this is "the same library wormhole-william itself uses."**
  That cannot be right as stated: wormhole-william must interoperate with Python
  magic-wormhole, which uses the RFC 9382 constants. This library cannot. Worth
  correcting under the same "verify against `src/`, not the README" rule the
  project already applies to security claims.

### 2b. Scalar arithmetic is not constant-time

`ed25519group/extended.go:295-319`, `ScalarMultFast`, is a recursive
double-and-add branching on `IsEven(s)` at `:305` — one recursion level per bit,
plus an extra `AddNonUnified` on every set bit. Runtime is a direct function of
the scalar's bit length and Hamming weight. Everything underneath is `math/big`,
which is not constant-time either.

There are no secret-indexed table lookups, because there are no tables.

Measured, best-of-5 on a warm loop:

```
scalar HW=1   (2^251)   : 517.781µs
scalar HW=252 (2^252-1) : 1.030508ms      ratio 1.99x

real pairing-code scalars: fastest 742.774µs ("05-word-word"),
                           slowest 819.684µs ("17-word-word"),  spread 10.4%
```

The 10.4% spread is across scalars derived from actual `NN-word-word` codes. The
leaking scalars are `s.passwordScalar` — used at `gospake2.go:197` in `Start`
and `:376` in `Finish`, derived straight from the pairing code — and
`s.xyScalar`, the ephemeral secret. Leaking the password scalar's Hamming weight
partitions a 22.6-bit dictionary; leaking `xyScalar` is worse, because
`pw·M = X* − x·B` then falls out and the dictionary attack is fully offline.

Limits, stated plainly: the channel was measured, an end-to-end attack was not
built, and over a real network this is noisy. But a PAKE whose scalar
multiplication is a variable-time ladder over `math/big`, operating on a
password-derived scalar, is disqualified by construction regardless of how hard
the measurement is from any particular vantage.

### 2c. Point validation

`ed25519group/ed25519.go:132-148` does perform both checks:

- `Cmp(&Zero)` at `:137` rejects the identity.
- `ScalarMult(L)` at `:141-144` is a genuine prime-order-subgroup check.

Empirically these work on the classes that could be tested: **200/200**
torsion-tainted points (`s·B + T₈`, order 8L) rejected, **291/291**
off-curve/twist points rejected, 0/4000 random 32-byte strings wrongly accepted.

Three problems sit on top.

**The Decompress error is discarded.** `ed25519group/ed25519.go:134` is
`affinePoint.Decompress(b)` with no assignment. `affine.go:152-154` computes
`IsOnCurve()` and returns `&NotOnCurve{}`; the caller throws it away. Off-curve
points survive to the subgroup check on luck. Today the subgroup check catches
them — defence-in-depth being spent to cover a discarded error.

**`Finish` panics on hostile input, 7 of 8 frames tried:**

```
empty frame                        -> PANIC: index out of range [0] with length 0
side byte only                     -> PANIC: nil pointer dereference
truncated element (16 bytes)       -> PANIC: nil pointer dereference
oversized element (64 bytes)       -> PANIC: nil pointer dereference
low-order point (order 2)          -> PANIC: nil pointer dereference
all-zero element                   -> PANIC: nil pointer dereference
low-order point (order 4)          -> PANIC: nil pointer dereference
bogus side byte 0x00 + valid elem  -> err=<nil> key=32 bytes
```

The empty-frame panic is `gospake2.go:339`, `msg[0]`, unguarded. The rest are
`ed25519group/extended.go:38-40`:

```go
zinv := new(big.Int).ModInverse(e.Z, Q)
X := new(big.Int).Mul(e.X, zinv)
```

`ModInverse` **returns nil** when `Z ≡ 0 (mod Q)`, and the next line dereferences
it. Low-order inputs drive `Z` to zero inside the ladder — and `ScalarMultFast`
is used for the subgroup check despite its own doc comment at
`extended.go:290-294` stating it "will give incorrect answers when called with
the points of order 1/2/4/6/8". The check is implemented with a routine
documented as invalid for exactly the inputs it exists to reject.

These are *targeted* inputs, not fuzz flakes: 0 panics in 4,000 random strings,
6 panics in 8 chosen ones. It is a remote unauthenticated crash of the pairing
process, on the one input path the hostile relay fully controls.

**No length or canonicality validation.** `Finish` never checks `len(msg)`; the
ed25519 `ElementFromBytes` never checks `len(b)`; `Decompress` never checks
`y < Q`, so non-canonical encodings are accepted as points. `spakeerror.go:9,12`
declares `WrongLength` and `CorruptMessage` and **neither is ever raised anywhere
in the library** — matching the `// TODO Corrupt exchange message needs to be
handled` at `gospake2.go:337`. Upstream knew and never finished it.

**Cofactor:** not handled. Rejecting non-prime-order points is a legitimate
alternative to cofactor clearing and is what this code does, so this is
defensible — but it means the crash-prone check is the whole defence.

---

## 3. Protocol logic in `gospake2.go`

This is the healthiest part of the library.

**Transcript binding is correct.** `transcriptAsymmetric` (`:213-238`) hashes
`SHA256(pw) ‖ SHA256(idA) ‖ SHA256(idB) ‖ first ‖ second ‖ K`. Password, both
identities and both messages are all bound. Role ordering is right: `:380` and
`:382` pass `(s.message, inbound)` for A and `(inbound, s.message)` for B, so
`first` is always A's message regardless of who computes it. This matches
python-spake2's construction. **No missing binding.**

**Symmetric ordering is correct.** `:255` sorts by `bytes.Compare`, so both sides
agree on order without knowing who is who.

**No oracle in the error paths.** Every early return in `Finish` — element
rejection at `:342`, reflection at `:347`, side mismatch at `:352-368` — happens
**before** `s.passwordScalar` is touched at `:370`, and depends only on
attacker-supplied and public state. The distinguishable error strings leak
nothing about the password. The panics are far more distinguishable than any
error string, but they too fire before password use, so they are a DoS rather
than a password oracle.

Three real defects:

- **`:217`, `elementSize := len(key)`.** The transcript's field width is taken
  from the length of the *shared secret's encoding*, not the group's element
  size. With the variable-length encoder, ~1 session in 315 hashes a transcript
  whose message fields are silently one byte short. Both sides truncate
  identically so the key still agrees — but the transcript no longer commits to
  the full messages.
- **`:339-368`, the side byte is never validated to be one of A/B/S.** A frame
  with side byte `0x00` passes every branch and produces a key. The byte is also
  not in the transcript, so it is unauthenticated.
- **`ed25519group/ed25519.go:114`, `s.Mod(s, L)` mutates the caller's `big.Int`
  in place.** Benign today because every scalar passed in is already reduced, but
  `Start` and `Finish` both hand it fields of the live `SPAKE2` struct. A
  landmine for anyone who later passes a shared or unreduced scalar.

Dead weight: `group.go` is an orphaned duplicate of the `groups.Group` interface
using `interface{}`, referenced by nothing.

---

## 4. Timing in `Finish`

**No early return depends on secret data** — all three are on public or
attacker-supplied values, and all precede password use. There is no MAC
comparison in this library at all, so there is no non-constant-time compare.

**But `Finish` is not constant-time with respect to the password**, for the
reason in §2b: `:376` runs `ScalarMult(s.unblinding, minuspw)` where `minuspw`
is the negated password scalar, through the same variable-time ladder. The leak
is in the arithmetic, not the control flow.

Separately, relevant to `DESIGN.md`: **this library provides no key-confirmation
step.** `Finish` returns a key and stops. The design's requirement that "the SAS
is displayed only after the SPAKE2 key-confirmation MACs verify" must be built on
top, whatever is used underneath.

---

## 5. What could NOT be determined

**The field arithmetic was not verified correct across its input space.**
Verified: Q, L, D, I, Bx and By against known constants (the library's own
`const_test.go` passes); that `ScalarMultFast` and `ScalarMultSlow` agree on the
cases tried; and that 6,000 full handshakes agree on the key. That is **not** a
proof that `Double`, `AddUnified` and `AddNonUnified` are correct for all inputs.

Treat "the curve arithmetic is correct" as **unestablished, not as passed.**
Given the findings above, further effort there was not the best use of the
review — but it is not being reported as clean.

**The discrete logs of the vendored M and N are unknown to this review.** No
small log to B exists (checked to 4096) and no derivation was found. Absence of
a *discovered* relationship is not evidence there is none. The finding is the
missing provenance, not a demonstrated backdoor.

---

## Alternative

**Write the SPAKE2 layer on `filippo.io/edwards25519`, following RFC 9382.**
Roughly 150 lines. Mapped to the findings:

- **(1)** M and N come from RFC 9382 §4 as published 32-byte encodings —
  verifiable by anyone, which is the whole property.
- **(2), (5)** `edwards25519.Point.SetBytes` validates canonical encoding and
  on-curve membership and returns an error, with no panic path.
  `MultByCofactor` handles the torsion question directly.
- **(3)** `edwards25519.Scalar` operations are constant-time by design.
- **(4)** `Point.Bytes()` is fixed-width 32 bytes. The bug cannot be expressed.

Keep `gospake2.go:213-268` as a *reference* for what a correct transcript looks
like — it is right, and it is the one piece of this library worth reading twice.
But prefer RFC 9382's own length-prefixed transcript
(`len(A)‖A‖len(B)‖B‖…`) over the fixed-offset scheme, since fixed offsets are
what let finding 4 corrupt the transcript silently. RFC 9382 also specifies the
confirmation MACs that `DESIGN.md` requires and this library does not provide.

The `groups.Group` interface cannot be salvaged as a shim: it types every scalar
as `*big.Int`, which forces variable-time arithmetic at the interface boundary.
Swapping the backend means replacing the interface, at which point the ~60 lines
of protocol logic are the only thing being kept.

---

## Note for `NOTICE.md`

The decision to vendor rather than pin was correct and paid for itself
immediately. Pinning would have shipped all five findings.
