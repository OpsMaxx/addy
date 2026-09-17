# Independent cryptographic review — M1 spine

**Reviewed:** `internal/protocol/` and `internal/pair/` (including `pair/spake2/`),
against `docs/PROTOCOL.md` and `THREAT_MODEL.md`. Two files outside that scope
were read because a scope question could not be answered without them:
`internal/api/auth.go` and `internal/client/client.go` are where the `Authz`
structure is actually produced and checked.

**Date:** 2026-09-17. **Baseline:** `./scripts/check.sh` all green before and
after. Every finding below was proved with a throwaway `zz_*_test.go` probe that
was run and then deleted; `git status` is clean apart from this file.

---

## Verdict

**SHIP AFTER SPECIFIC FIXES.**

The roster verifier is sound against every one of the ten adversary cases §12
states, and I could not break it within its own stated inputs. The SPAKE2
implementation is the strongest single piece of code here — the RFC 9382
constants are correct, the cofactor handling is right, the refusal ordering is
genuinely non-oracular, and I failed to find anything wrong with it. The escrow
and handoff commitment discipline is correct and checked before the AEAD, as
specified.

What holds the verdict back is three things, and all three are places where the
code does less than the specification says, not places where the specification
is wrong:

1. `Handoff.Adopt` carries the anti-truncation anchor and then ignores it, so a
   joining device accepts a chain the handoff itself proves is short.
2. Nothing binds a handoff to the pairing that produced it, so the joining device
   cannot distinguish its pairing partner from anyone who watched the relay.
3. The specification's `MUST NOT accept small-order public keys` is not
   implemented anywhere, and the consequence is concrete: an authorised device
   can rotate to a degenerate epoch key and hand the server permanent authorship
   of the roster.

None of the three is subtle to fix. All three are in scope for M1 because they
are M1's own text.

---

## Findings

| # | Severity | What | Evidence |
|---|---|---|---|
| 1 | **High** | `Adopt` ignores the handoff's `HeadEntry`; a joining device accepts a truncated chain | `internal/protocol/handoff.go:201-229` |
| 2 | **High** | A handoff is not bound to the pairing; any party that saw the joiner's `DK_enc.pub` can adopt it into another account | `internal/protocol/handoff.go:88-116`, `:131-193`; `internal/pair/session.go:209-241` |
| 3 | **High** | No small-order / canonical public-key rejection, contrary to §1 and §5.7 step 9 | `internal/protocol/roster.go:346-353`, `:392` |
| 4 | **Medium** | `Authz`: no spent-nonce set, no session binding, no instance binding. `TS` is a symptom, not the disease | `internal/api/auth.go:250-262`; `internal/client/client.go:217-224` |
| 5 | **Medium** | Confirmation and SAS labels are unprefixed concatenations and the pairing frames enforce no key width, so two different key pairs produce identical `conf_A`, `conf_B` and SAS | `internal/pair/session.go:186-202`, `:169-171`; `internal/pair/sas.go:141-149` |
| 6 | **Medium** | Device labels sealed in an earlier epoch are unreadable after a rotation, which breaks §5.8's mandatory device review — the control the whole no-pin case rests on | `internal/protocol/genesis.go:32-57`; `internal/protocol/escrow.go:36-43` |
| 7 | Low | `pair.Limiter` exists but nothing calls it; `Begin`/`Reply` never count a `conf_B` failure or burn a code | `internal/pair/code.go:139-199`; `internal/pair/session.go` (no reference) |
| 8 | Low | The client places no size limit on the roster it fetches, and `VerifyChain` materialises every entry before checking a single signature | `internal/client/client.go:262-275`; `internal/protocol/roster.go:241-254` |
| 9 | Low | `Verified.Devices[].PubSign` / `.PubEnc` / `.LabelCT` alias the caller's chain buffer | `internal/protocol/roster.go:141-152`, `:366-369`; `internal/protocol/ace.go:143-154` |
| 10 | Low | `Verified.EpochEnc` is `nil` for any chain that has not rotated | `internal/protocol/roster.go:272`, `:429` |
| 11 | Info | The verifier accepts a root-signed hygiene rotation and a root-signed genesis; §5.3 and §10 step 6 say otherwise | `internal/protocol/roster.go:325-344` |
| 12 | Info | `Encoder.Str` normalises where `Decoder.Str` rejects; for `Authz.Path` that means the signature covers a string the server may not be the one it routes on | `internal/protocol/ace.go:80`, `:228-246`; `internal/api/auth.go:254-255` |

---

## 1. `Adopt` ignores the handoff's `HeadEntry` (High)

`internal/protocol/handoff.go:201-229`

The `Handoff` structure carries `HeadEntry` — "the roster head, body || sig,
verbatim" — for exactly one reason, spelled out in §5.8 item 3 for the escrow and
inherited here: it is the out-of-band anchor that makes a truncated chain
detectable. `Adopt` never looks at it. It calls
`VerifyChain(chain, h.AccountID, h.RootSignPub, epoch1, nil)` with a `nil` pin,
and a joining device has no pin by definition, so §5.7 step 12 does nothing
either. The joiner therefore has two anti-rollback controls available and uses
neither.

**Failure scenario.** Device C is compromised and soft-revoked at seq 2. The user
pairs a new device D with device A. A seals a handoff whose `HeadEntry` is the
revoke entry at seq 2. The server serves D a chain truncated at seq 1. Every step
of §5.7 passes: the genesis is a genesis, the sequence is contiguous from zero,
every link hashes, every signature verifies — the truncated chain is genuinely
valid, which is the whole point of case 7. D adopts a device set that still
contains C. D will now accept C's signalling (§4.4), and on the next epoch
transition D will seal `AK_{n+1}` to C's `DK_enc` as a "surviving device"
(§9.1 step 4).

Probe result:

```
FINDING: Adopt accepted a chain truncated before the revoke named by the
handoff's own HeadEntry; revoked device is still in the device set
(head seq 1, handoff head is seq 2)
```

**Second half of the same gap.** `Adopt` also never compares `h.Epoch` against
the verified chain's epoch. A handoff for epoch 1 served against a chain that has
rotated to epoch 3 returns epoch-1 keys and a `Verified` at epoch 3, with no
error and nothing telling the caller the two disagree.

**Fix.** In `Adopt`: hash `h.HeadEntry` with `Entry.Hash` semantics, require that
the verified chain contains that hash at some `seq`, and require
`v.HeadSeq >= that seq`. That is precisely the `Pin` check that already exists —
the handoff is a pin, delivered under HPKE, and can be passed to `VerifyChain` as
one. Also require `v.Epoch == h.Epoch`. `OpenEscrow` documents step 7 as "the
caller's, because it needs the chain"; `Adopt` *is* the caller and *has* the
chain, so the same excuse does not apply.

---

## 2. A handoff is not bound to the pairing that produced it (High)

`internal/protocol/handoff.go:88-116` (seal), `:131-193` (open)

The handoff is HPKE-sealed to the joiner's `DK_enc` public half with
`info = "addy-handoff-hpke-v1\0" || account_id || u64(epoch)` and
`aad = account_id || epoch || counter`. The exporter commitment covers the same
three values. Not one of them is a secret, and none of them comes from the
pairing. Sealing requires only the joiner's *public* encryption key.

The joiner publishes that key in the clear on frame 2
(`ReplyFrame.PubEnc`, `internal/pair/session.go:117-122`), on a channel the
threat model says is relayed by the adversary.

**Failure scenario.** The relay observes frame 2 and learns B's `DK_enc.pub`. It
drops frame 3, so B never confirms and never sees a SAS. It then delivers a
handoff of its own, for an account it minted itself, sealed to B's key.
`OpenHandoff` succeeds: the suite is right, the commitment reproduces, the
plaintext's `account_id`/`epoch`/`counter` match the ones the relay also supplied,
and `DeriveAccountID(out.RootSignPub) == out.AccountID` holds because it is the
attacker's own root key. `Adopt` then verifies the attacker's chain from its own
genesis, against the attacker's root key, and returns a clean `*Verified`. B is
now a device of the attacker's account and syncs into it.

Probe result:

```
FINDING: a handoff from a party that never completed the PAKE opened and
adopted cleanly; nothing in the handoff binds it to the pairing session
```

**Honest mitigation.** `Joiner.SAS()` refuses until `j.done`, so a joining device
that refuses to adopt before the human has compared emoji is safe. But that is a
procedural control enforced by code nobody has written yet, in a design whose
stated position is that the crypto carries the claim and the emoji are only a
tripwire (§8.5). The relay also gets to choose *when* B sees this, and dropping
frame 3 is free — I confirmed the one-sided state:

```
NOTE: the initiator is fully confirmed and holds the joiner's DK_enc while the
joiner has confirmed nothing; the relay learned the joiner's DK_enc.pub from
frame 2 in the clear
```

**Fix.** Mix the pairing secret into the handoff. The cleanest version costs one
line: add the PAKE shared secret (or `conf_A`, which is already derived from it
and already binds both identity keys and `pairing_id`) to the HPKE `info` string
for the pairing handoff. `Initiator.Secret()` and `Joiner.Secret()` already
expose it. A handoff then opens only for a party that completed the PAKE, and the
"any party who saw the public key" class disappears rather than being deferred to
the UI. The epoch-handoff and `SealTo` paths keep the current `info`, since those
have no pairing — which argues for a distinct domain prefix for the pairing
handoff, in keeping with §14 item 2.

---

## 3. Small-order public keys are accepted (High)

`internal/protocol/roster.go:346-353` and `:392`

§1 is unambiguous: "Ed25519 verification MUST reject non-canonical encodings and
MUST NOT accept small-order public keys… a verifier that accepts a small-order
`pub_sign` in a roster entry would accept a device nobody holds a key for."
§5.7 step 9 repeats it. The check exists nowhere in the tree. `VerifyChain` calls
`ed25519.Verify` directly, and `crypto/ed25519` does not reject small-order `A`:
with `A` the identity point the verification equation `[S]B = R + [k]A` collapses
to `[S]B = R`, which anyone can satisfy.

I confirmed the primitive behaviour first:

```
precondition: crypto/ed25519 accepts a forged signature under the identity point
```

**Failure scenario, the one that matters.** `roster.go:392` installs an
`op = epoch` entry's `pub_sign` as the epoch's verification key for the rest of
the chain. A device that holds `AK_n` — an authorised device, perhaps one that is
about to be revoked — publishes a hygiene rotation whose `AK_{n+1}.sign.pub` is
the identity point. The entry is validly signed under `AK_n.sign`, so it passes
steps 6 through 9. From seq+1 onward, **the server can author roster entries**:
every signature under the epoch key verifies trivially. It can add devices,
revoke devices, and re-admit the device that was revoked. That is the headline
claim — "the server cannot add a device" — falling to an insider who never needed
the root key.

```
FINDING: the server authored a roster entry with no account key. VerifyChain
accepted a small-order AK_2.sign from the epoch entry, and every signature
verifies trivially under it
```

The second, lesser case is a plain `op = add` whose `pub_sign` is degenerate:

```
FINDING: a device whose DK_sign is the identity point is in the verified device
set; any party can forge that device's login, authz and signalling signatures
```

That device's `addy-login-v1` and `addy-authz-v1` signatures are forgeable by
anyone, including the server, which is §1's "a device nobody holds a key for"
stated as an outcome rather than a worry.

**Fix.** One helper, called from step 9 before `ed25519.Verify`, and from the
`OpEpoch` branch before installing the key: decode `pub_sign` with
`edwards25519.Point.SetBytes`, require the re-encoding to equal the input (the
canonicality check — `filippo.io/edwards25519` does not do it, as
`pair/spake2/spake2.go:211-228` already discovered and documents), and reject
when `MultByCofactor(P)` is the identity. The SPAKE2 package already contains
exactly this code; the roster should use the same helper rather than a second
copy. `filippo.io/edwards25519` is already a direct dependency.

The same check belongs on `pub_enc`: `x25519Public` (`keys.go:227-230`) is only
called from `Rotation.SealTo`, so a roster entry's `pub_enc` is never validated as
a curve point at verification time.

---

## 4. `Authz` has no freshness and no session binding (Medium)

`internal/api/auth.go:250-262`, `internal/client/client.go:217-224`

The brief asked whether `Authz.TS` being zero is a replay problem and what the
real fix is. The answer is that `TS` is neither the problem nor the fix. §2.6
makes `ts` display-only everywhere and forbids anything load-bearing from
depending on a clock; setting it to a real timestamp would change nothing, and
*using* it for validity would violate the spec. The problem is elsewhere and it
is real.

§4 item 2 says "every signature covers a client-contributed nonce: 32 bytes from
the signing device, fresh per signature". The client does draw a fresh nonce.
The server never records that it spent one. `authed` looks up the bearer token in
`s.auth.sessions` and verifies the signature; there is no equivalent of the
`s.auth.challenges` map that `login` maintains and deletes from on use
(`auth.go:140-142`). So the nonce buys nothing.

Measured, against a live instance:

```
same nonce, same session, four times: [200 200 200 200]
same nonce and signature under a SECOND session: 200
FINDING: the identical device_nonce was accepted 4 times
FINDING: the same authz signature was accepted under a different session token;
nothing binds an authorization to the login that carried it
```

Three separate gaps, in increasing order of how much they cost:

- **No spent-nonce set.** A captured authed request replays indefinitely. The
  mundane read case is bounded (a replayed `GET` returns current data) and the
  write case happens to be caught by the store's own monotonic counter
  (`resources.go:162-171` returns 409), but that is an object-level control doing
  an authentication control's job, and it only covers objects.
- **No session binding.** The signature does not cover the bearer token or any
  session identifier, so a signature outlives the login that carried it. Combined
  with the above, one captured signature is a standing capability for as long as
  *any* session for that device is live.
- **No instance binding.** `Login` carries `server_spki` and `Authz` does not —
  §4.1 argues at length for why the login needs it, and §4.2 silently omits the
  same argument for the authorization. An authz signature is valid against any
  instance serving the same `account_id`.

**Fix.** A spent-nonce set keyed on `(device, device_nonce)`, swept on the same
TTL as the session, is the direct control and costs one map beside the two that
already exist. Adding `server_spki` to the `addy-authz-v1` structure closes the
third; that is a spec change, so it belongs in §4.2 rather than only in code.

The same shape applies to `addy-signal-v1`: an offer carries a zero `peer_nonce`
by construction (§4.4), so an offer is replayable unless the receiving peer keeps
a spent-nonce set of its own. That enforcement lives outside this review's scope,
but the fix should land once, not twice.

---

## 5. The confirmation and SAS labels are ambiguous (Medium)

`internal/pair/session.go:186-202`, `internal/pair/sas.go:141-149`

Both labels are built as `label || 0x00 || pairing_id || initPubSign ||
joinPubSign` with no length prefixes. §8.4 and §8.5 declare all three as
fixed-width, but nothing enforces it: `Join` checks only that
`f.PubSign` is non-empty (`session.go:169-171`), `Reply` does not check
`f.PubSign` at all (`session.go:209-241`), and `Begin` accepts any byte string as
the local key.

Consequence: for any `x`, the pair `(initPub = A, joinPub = x‖B)` and the pair
`(initPub = A‖x, joinPub = B)` build the same label, so they produce the same
`conf_A`, the same `conf_B` and the same seven emoji.

```
FINDING: two different key pairs produce identical confirmations
FINDING: the SAS collides for the same reason; the emoji tripwire shows
identical symbols on both screens while the two devices disagree about each
other's signing key
FINDING: a full pairing completed with 12-byte and 10-byte signing keys and a
9-byte encryption key
```

**How bad this is, honestly.** Not currently exploitable, and I want to be
precise about why rather than inflate it. To use the collision a relay must
complete the PAKE with both sides, which requires the password — and a relay that
has the password is a full MITM regardless. The downstream `Entry.Encode` also
refuses a `pub_sign` that is not 32 bytes (`roster.go:78-87`), so the spliced key
could not be published. Two accidental defences, neither of them this one.

What it does cost is the property §8.4 states in its own words: "the confirmation
binds the PAKE result to the two keys the devices are about to trust". That
sentence is false for variable-length inputs, and the existing test
`TestASubstitutedIdentityKeyBreaksConfirmation` only exercises the equal-length
case, so nothing in the suite would notice.

**Fix.** Reject any `PubSign` that is not `ed25519.PublicKeySize` and any
`PubEnc` that is not 32 bytes, at `Begin`, `Join` and `Reply`. Length-prefix the
label components as well — ACE-1 already has the primitive, and `spake2.go`'s own
transcript (`writeLen`, `:287-292`) makes exactly this argument for exactly this
reason.

---

## 6. Rotation orphans device labels, breaking the mandatory device review (Medium)

`internal/protocol/genesis.go:32-57`, `internal/protocol/escrow.go:36-43`

`SealLabel` seals a device's pseudonym under `K_profile_n` for the epoch the
`add` entry was written in, with the epoch in the AAD. §9 says an epoch
transition "changes the epoch and nothing else" — the roster is not re-sealed, so
an entry written in epoch 1 keeps a label that only `K_profile_1` opens.

The escrow blob carries `ak_seed` for one epoch (`Escrow.AKSeed`, a single
`fixed[32]`), and §6.8 requires a client that finds an escrow behind the roster's
current epoch to refuse to use the `AK` in it. So a device recovering at epoch
`n` can derive `K_profile_n` and nothing earlier.

**Consequence.** §5.8's control 1 — "the user is shown every device in the chain,
with its label and its fingerprint, and MUST confirm the set" — is the first of
the four mandatory controls for the no-pin case, which §12 case 7 identifies as
the one case where the cryptographic defence is simply absent. After a single
rotation, a recovering device can show the label for devices added in the current
epoch and a bare key fingerprint for everything older. §5.4 sanctions the
fingerprint fallback for exactly one situation — a device mid-pairing — and this
is not that.

The same applies to a device that joins at epoch `n`: it derives `K_profile_n`
from the handoff and can never read the labels of its siblings added earlier.

**Fix.** This is a specification question before it is a code one, so I am
flagging rather than prescribing. The options I can see: re-seal `label_ct` under
the new epoch as part of the transition (which contradicts "changes the epoch and
nothing else"); seal labels under a key that survives rotation; or carry the
chain of previous `AK`s in the escrow. The third is the smallest and the one I
would argue for — the escrow already exists to hold what is not derivable, and
"every `AK` this account has had" is exactly that. It also makes §5.8's other
three controls stronger rather than weaker.

---

## 7–12. The rest

**7 — the limiter is not wired (Low).** `pair.Limiter` implements §8.6 correctly
and is well tested, and nothing in `session.go` references it. Twenty consecutive
failed pairings left it untouched:

```
NOTE: 20 failed pairing attempts ran with the limiter untouched (remaining still
5); Begin/Reply never call Attempt or Burn
```

The PAKE's own single-use guard does hold — a second `Reply` on the same
`Initiator` is refused, so one `Begin` is one guess — but §8.6's "5 failed
attempts, counted by A as failures of `conf_B`" is not enforced by anything in
M1. The `Limiter` should be a field of `Initiator`, so that counting is not
something a caller can forget.

**8 — unbounded roster read (Low).** `Client.Roster` decodes the response with no
size limit (`client.go:262-275`); the only `io.LimitReader` in the client is on
error bodies (`:340`). `VerifyChain` step 1 parses the entire byte stream into
`[]Entry` before step 2 looks at the first entry, so unsigned garbage is fully
materialised before it is rejected. Measured amplification is modest — 50.8 MB of
input caused roughly 189 MiB of allocation before the genesis check refused it —
so the real exposure is the missing read cap, against precisely the adversary the
threat model names. Cap the roster read, and consider verifying entry-by-entry
rather than parse-all-then-verify.

**9 — the verified device set aliases the input (Low).** `Decoder.Fixed` returns a
subslice of the caller's buffer (`ace.go:143-154`), `DecodeEntry` stores those
subslices (`roster.go:141-152`), and `VerifyChain` copies the references into
`Device` (`roster.go:366-369`). Scribbling over the chain buffer after
verification changes the verified device set:

```
FINDING: Verified.Devices[0].PubSign aliases the input buffer; it changed from
8a88e3dd7409f195 to aaaaaaaaaaaaaaaa when the caller reused it
```

No caller reuses the buffer today. It is the kind of thing that stays harmless
until someone adds a pooled reader, and one `bytes.Clone` in the `OpAdd` branch
ends it.

**10 — `EpochEnc` is nil at epoch 1 (Low).** `epochEnc` is populated only by
`OpEpoch` entries (`roster.go:272`, `:393`), so `Verified.EpochEnc` is `nil` for
any chain that has never rotated, while `EpochSign` is correctly the pinned
epoch-1 key. A caller that reaches for `EpochEnc` to seal something gets a nil
slice rather than an error. Seed the map the way `epochSign` is seeded, or drop
the field.

**11 — signer-table deviations (Info).** §5.3 says a hygiene rotation is signed
by `AK_{epoch-1}.sign` and §10 step 6 says genesis is signed by `AK_1.sign`. The
verifier accepts `SignerRK` for both. Neither is a hole — `RK_sign` outranks
`AK_n` everywhere, and a root-signed genesis is correctly reported as
`MnemonicAuthored`. It is worth writing down because it means the
`REVOCATION_ROTATION` flag, not the signer field, is the only thing a reader can
use to tell the two kinds of rotation apart — which is what
`ReadChainedHandoff` already relies on (`rotate.go:171-179`), correctly.

A related note on `PrepareRotation` (`rotate.go:58-117`): the `Revocation` branch
checks that `signerKey` is the root key, and the `Hygiene` branch checks nothing
at all. Passing the wrong key produces an entry that no verifier will accept, so
it fails closed, but the asymmetry is worth closing since the check is one line.

**12 — `Str` normalises on encode and rejects on decode (Info).**
`Encoder.Str` applies `norm.NFC.String` (`ace.go:80`) while `Decoder.Str` refuses
anything not already NFC (`ace.go:241-244`). That asymmetry is deliberate and
tested. Its consequence for `Authz` is worth stating anyway: the server builds
`Authz.Path` from `r.URL.Path` and signs over the NFC normalisation of it
(`auth.go:254-255`), so the bytes verified are not necessarily the bytes the mux
routed on. Object names are currently hex and ASCII, so there is nothing to
exploit; if a collection name ever becomes user-supplied UTF-8, one signature
would authorise two distinct paths. Normalising on the *encode* side is the
dangerous direction for a value that is signed and then acted on.

---

## What held up

Stated plainly, because a review that only lists problems misrepresents the code.

- **The roster verifier's step order is correct.** I walked all thirteen steps
  against §5.7 looking specifically for a check that happens after something it
  should gate. Signature verification (step 9) precedes every op-semantics
  mutation (step 10), so a forged transition entry cannot install an epoch key —
  `epochSign[e.Epoch] = …` at `roster.go:392` is unreachable without a valid
  signature under `RK_sign` or `AK_{epoch-1}.sign`. The epoch key map, which the
  brief singled out, is not attacker-influenceable.
- **No integer overflow on `seq` or `epoch`.** `e.Epoch - 1` at `roster.go:338`
  cannot underflow: step 2 pins the genesis epoch at 1, step 6 admits only
  `currentEpoch` or `currentEpoch+1`-with-`OpEpoch` thereafter, and the `OpEpoch`
  branch is unreachable at `i == 0`. `int(pin.Seq)` at `roster.go:410` is bounded
  by the preceding `last.Seq < pin.Seq` check and `seq == i`.
- **Nil keys are handled explicitly, not by accident.** `roster.go:327-329`
  refuses a root-signed entry with no root key, and `:341-343` tests `pub == nil`
  as well as map presence, which is what stops a `nil` epoch-1 key from being
  used. This is the one place I expected to find a nil-treated-as-valid bug and
  did not.
- **Signature purpose separation is real.** Four distinct domain prefixes, each
  the first bytes of the signed message, each tested negatively.
- **SPAKE2.** `M` and `N` are byte-identical to RFC 9382 §4, both decode to
  canonical points with a prime-order component. The transcript is RFC 9382's,
  with 8-byte little-endian length prefixes on all six components, binding both
  identity strings, both messages, the group element and the password scalar.
  `MultByCofactor` is used correctly: clearing after `ScalarMult(x, ·)` still
  annihilates a torsion component, because `8·x·T = x·(8·T) = O`, and I confirmed
  the honest-run agreement and the tainted-run divergence experimentally. The
  single-use guard is set before any error return, so a failed `Finish` consumes
  the state. Refusal ordering is genuinely non-oracular — I ran five classes of
  hostile frame under two different passwords and every refusal was
  byte-identical. The canonicality check at `:226-228` is a real catch that
  `filippo.io/edwards25519` does not do for you, and the code says so.
- **Escrow and handoff commitment discipline.** The exporter tag is computed and
  compared with `subtle.ConstantTimeCompare` before `Open` in both
  `OpenEscrow` (`escrow.go:191-204`) and `OpenHandoff` (`handoff.go:158-169`).
  The counter is inside the exporter context, so a server lying about it is
  caught by the commitment rather than by a later field comparison — the code
  comment claims this and it is true. The plaintext/AAD cross-check afterwards is
  redundant belt-and-braces, correctly placed.
- **`OpenHandoff`'s account binding.** `DeriveAccountID(out.RootSignPub) !=
  out.AccountID` (`handoff.go:189-191`) is the check the 2026-09-17 correction
  added and it does what it says. It does not help against finding 2, because an
  attacker sealing their own account satisfies it — that is a different property.
- **ACE-1 strictness.** All seven refusals in §2.3 are implemented and the
  error-poisoning decoder pattern means a half-decoded structure cannot be acted
  on. `Bytes()` guards the `u32`-to-`int` conversion for 32-bit platforms.
- **The existing adversary suite is not theatre.** Cases 1, 2, 3, 4, 6, 6b, 7, 8,
  9 and 10 from §12 each have a test that fails for the right reason. My findings
  are in the gaps between those cases, not in them.

---

## What I could not determine

- **Whether findings 1 and 2 are live in a shipping product.** `Adopt`,
  `OpenHandoff`, `SealHandoff`, `OpenCollection` and `SealCollection` have no
  non-test callers in the tree. The joining flow and the sync flow are not
  written yet. I reviewed the API contracts as the thing M2 will be built on, and
  both findings are about what that contract permits. A caller that happens to do
  the right thing would mask both, and no caller exists to check.
- **Whether the TypeScript side agrees.** §13.4 says SPAKE2 is covered by a
  Go/TypeScript interop test rather than a vector. I did not find a TypeScript
  implementation in this repository and could not run that test, so
  "two independent implementations interoperate byte for byte" is unverified by
  me. The `w`-scalar derivation (`deriveW`, SHA-512 then `SetUniformBytes` under
  an `addy-pake-w-v1` label, `spake2.go:128-147`) is a choice the specification
  explicitly leaves open; if the TypeScript side reduces differently, the two
  will disagree and the failure will look like a wrong code.
- **Constant-time behaviour at the machine level.** I read for constant-time
  *construction* — `subtle.ConstantTimeCompare` at every comparison that matters,
  `filippo.io/edwards25519`'s constant-time scalar arithmetic — and found it
  consistently used. I did not measure. The prior review's 1.99x timing ratio was
  found by measurement, and nothing here has been measured the same way.
- **The exploitability ceiling on finding 5.** I established that the labels
  collide and that the pairing completes with malformed key widths. I did not
  construct an end-to-end attack, and I do not believe one exists today, for the
  reasons given in that section. If the roster's `fixed[32]` check were ever
  relaxed, I would expect that conclusion to change, and I have not tried to prove
  it could not.
- **The "second door" (§6.7).** `AK_n` sealed to an optional second recovery
  recipient, and the `escrow-alt` object name in §11, are not implemented. §6.7
  is written as a MUST-shaped argument about an optional recipient, and I could
  not tell from the text whether M1 was meant to carry it. Flagging rather than
  scoring it.
- **Case 5 of §12 end to end.** "An injected transcript fault produces mismatched
  SAS ⇒ abort *before* `AK_n` is sealed." The first half is tested in
  `internal/pair`. The second half is not tested anywhere and is not enforceable
  anywhere in the current code — `SealHandoff`'s doc comment says the ordering
  "is the caller's to enforce". Binding the handoff to the pairing secret
  (finding 2's fix) would turn that comment into a mechanism, which is the main
  reason I would take that fix over the alternatives.

---

## Suggested order of work

1. Finding 3 — the small-order check. Smallest diff, largest claim protected, and
   the helper already exists in `pair/spake2`.
2. Finding 1 — `Adopt` honours `HeadEntry` and `h.Epoch`. It is the `Pin` check
   that is already written.
3. Finding 2 — bind the pairing handoff to the PAKE secret. This one changes
   `PROTOCOL.md` §8.7, so it needs the spec edit alongside it, and it is the fix
   that also makes §12 case 5's second half testable.
4. Finding 4 — a spent-nonce set for `authz`, matching the one `login` already
   has.
5. Finding 5 — width checks and length-prefixed labels in `internal/pair`.
6. Finding 6 — a specification decision about labels across epochs, before code.
7. The Lows, together, when something else is already touching those files.
