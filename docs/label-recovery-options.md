# Device labels across epochs — the options, judged on the crypto

m1-review finding 6: `label_ct` is sealed under `K_profile_n`, `K_profile_n` is
derived from a rotating `AK_n`, and the escrow carries exactly one `AK`. A device
recovering at epoch `n` therefore reads the labels of devices added in epoch `n`
and shows a bare hex fingerprint for everything older — at the one moment §5.8
makes a human device review mandatory.

This document judges the candidates on the cryptographic and threat-model side
only. Implementation cost and UX are somebody else's paper.

---

## Recommendation, in one line each

**First choice — split the label key off `K_profile`, per epoch, and carry the
history where `AK` already travels.** Add `K_label_n = HKDF(AK_n, "addy-label-v1\0"
|| account_id || u64(n))` and put `K_label_1..n` in the escrow blob and in the
handoff. It changes no roster byte, no signature, no AAD, and it is the only
option that gives a recovering device every label without giving a revoked device
anything it does not already hold.

**Second choice — option C, labels as a T0 collection.** Mechanically the
cleanest (it inherits rotation, the anti-rollback counter and the schema rule for
free) but it takes the label out from under the roster signature, so the printed
card's head hash stops committing to it — a real loss in the exact scenario being
fixed.

**Option D is a floor, not an alternative.** Every option keeps a fingerprint
fallback for some transient case, and hex is a bad fallback. Render `pub_sign` as
five EFF words under its own domain separator regardless of which option wins.
But D alone does not close the finding, for a reason given below that is worth
reading before anyone reaches for the cheap fix.

---

## What the label is actually for, which decides how bad this is

The label does **not** authenticate a device, and cannot. To author an `add`
entry an attacker needs `AK_n.sign` or `RK_sign`; either one also gives them
`K_profile_n`, so a hostile device arrives with a label of the attacker's
choosing. `my-laptop` next to a key the user has never seen is exactly as easy to
produce as `quiet-otter-41`.

So the label's job at the §5.8 review is **recognition**, not verification: the
user is checking *"these are the four devices I remember, named as I remember
them"*. That is a check against **truncation** — a chain missing the phone — and
it works because the user has a memory of the names and no memory of the keys.

This cuts both ways.

- It weakens the finding's framing. The label was never a defence against an
  added device.
- It kills option D as a complete answer. A five-word phrase derived from
  `pub_sign` is a string the user has never seen before and has no memory of.
  It makes the fingerprint *comparable* (which is worth having, for the
  mid-pairing case in §5.4 and for any residual fallback) but it does not make a
  missing device *noticeable*. The roster-head phrase works because it is
  compared between two windows in the moment; a per-device phrase has nothing to
  be compared against.

The finding stands. It is a Medium, correctly rated, and the cheap option does
not hold.

### Addendum: what changes if the review becomes selection

The UX review argues, correctly, that **a truncated chain contains no forged
entries** — every device in it genuinely was the user's — so "do you recognise
these?" earns a truthful yes and the truthful yes is the wrong answer. What
truncation hides is a *revocation*: the sold laptop still reads as live. The
question the user can actually answer is not "is one missing" but "have you got
rid of any of these", and that is recall with a cue rather than detection of an
absence.

If §5.8 control 1 is restated as **re-admission, default off** — every device
unchecked, the output being which devices get `AK_{n+1}` sealed to them — then
labels matter *more*, not less, and for a better reason:

- The task becomes per-device recall, and the label is the cue. A key
  fingerprint cues nothing.
- **The failure mode inverts to fail-closed.** Under bulk confirmation, an
  unreadable label pushed the user toward a blanket yes. Under default-off, a
  label the user cannot place leaves the box unchecked, costing a re-pair rather
  than a compromise.
- It neutralises the attacker-chosen label. A device added by a holder of `AK_n`
  arrives with a name of the attacker's choosing; under bulk confirmation that
  label was both the aid and a channel the attacker controlled, and under
  default-off it can only fail to persuade.

That last point is what makes the label safe to lean on at all, and it should be
stated honestly in both directions: it also **demotes the label from a security
control to a usability aid whose failure is safe.** The work below is still worth
doing — one HKDF label and one escrow field — but it is no longer load-bearing,
and it should not be priced or scheduled as though it were. Its remaining value
concentrates on devices that cannot simply be re-paired in the moment: the
headless box, the machine at another site. For everything the user can walk over
to, re-pairing is the better answer and the label is a convenience.

---

## Option-by-option

### A — one epoch-independent `K_label` derived from the root

**Rejected, and it is the worst of the five.**

1. **Revocation.** `K_label` never rotates, so a device that holds it holds it
   forever, including for every device added *after* its revocation. That is a
   permanent forward leak past a revocation — precisely the thing the epoch
   machinery exists to create (§12 case 6). Today a revoked device's view of the
   estate freezes at epoch `n`; under A it keeps watching the estate grow, by
   name, forever. DESIGN.md:346 sanctions renaming a device to something
   identifying *because the label is encrypted*, so the plaintext is
   user-controlled and may be PII.
2. **Distribution makes it worse.** `K_label` is derived from the BIP39 seed,
   and paired devices do not hold the seed — that is the whole premise of §6. So
   `K_label` has to be pushed to every device through pairing and handoff, which
   puts **root-derived, never-rotating material into every device's
   `safeStorage`** — storage §12 case 6 states outright is readable by anything
   running as the user. A is the only option that moves the root's descendants
   onto devices.
3. **Forward secrecy (question 4).** The per-label plaintext is a two-word
   nickname, so the direct confidentiality loss is small. The structural loss is
   not: a non-rotating key is one whose compromise window is the lifetime of the
   account, and it creates a class of data exempt from revocation in a design
   whose entire discipline is that nothing is exempt. The answer to "does it
   matter when the plaintext is a nickname" is that it matters *less for the
   nickname and more for the precedent* — and there is no reason to accept
   either, because the first choice below costs less and leaks nothing.

### B — re-seal historical labels at each transition, as a separate object

Workable, and not the contradiction the review worried about: §9.1 step 2 already
re-seals every T0 collection under `K_profile_{n+1}`, so re-sealing is what a
transition already does to data. "Changes the epoch and nothing else" governs the
*entry*, not the payloads.

- **Signature (question 3).** Fine. The side-car is a new object; the entry's
  `label_ct` is untouched, so no existing signed byte moves. Nothing here is a
  non-starter.
- **Revocation.** Fine. The side-car is under `K_profile_{n+1}`; a device revoked
  at `n` cannot open it and gains nothing forward.
- **Server view.** One extra object sized `O(devices)`. The server already knows
  the device count exactly from the chain, so nothing new leaks — provided it is
  **one** blob and not one object per device, which would turn a count the server
  already has into a per-device correlator it currently does not.

**Why it is not the pick.** It creates two sources of truth for one label. The
entry's `label_ct` is authoritative and signed; the side-car is a copy the server
can serve stale. A client must then decide which wins, and §9 says exactly what
that costs: *"a combined operation is one where a verifier has to decide which
half it is checking, and that decision is where the hole goes."* The rule can be
written ("the entry wins when openable, the side-car only when `entry.epoch !=
current`") but it is a rule, and the first choice needs none.

### C — labels move into a T0 collection keyed by `pub_sign`

The strongest of the listed candidates, and my second choice.

- **Signature (question 3).** No existing entry is mutated, so it is not a
  non-starter — but it *is* a wire-format change: `label_ct` becomes zero-length
  for `add` too, and §5.7 step 10's "`label_ct` non-empty for `add`" inverts.
  That is a signed-body change and therefore a protocol version bump. Affordable
  pre-M1; not affordable later.
- **Revocation.** Fine, and for free: the collection re-seals under
  `K_profile_{n+1}` at §9.1 step 2 like everything else.
- **Server view.** One more collection object, same shape as the others. The
  device count is already public. No new channel.
- **`pub_sign` binding (question 5).** Survives, and gets *stronger*. The whole
  map is under one AEAD tag with `pub_sign` as the key, so two labels cannot be
  swapped without breaking the tag at all — where the per-entry AAD only makes a
  swap detectable, the single-object form makes it impossible.
- **Everything else comes free:** rotation ordering, the monotonic counter, the
  `collection`-in-AAD binding, the schema/read-only rule.

**The disqualifier.** The label stops being covered by the roster signature. Today
`label_ct` is inside the signed body, so it is authenticated as authored by the
account key at the moment of `add`, and the **printed card's head hash commits to
it**. Under C the card commits to keys and nothing else, and the label shown at
the §5.8 review comes from a mutable object with no out-of-band anchor. The server
still cannot *forge* a label — it holds no `K_profile` — but it can serve a stale
collection and therefore omit or age the names, in the one ceremony §5.8 exists to
protect and where the client by definition has no counter history to catch a
rollback with. Trading a signed value for an unsigned one at that exact moment is
the wrong direction, even though every other property improves.

### D — keep `label_ct`, make fingerprints human-comparable

See "what the label is actually for" above: this makes the fallback legible
without making a missing device noticeable. Take it anyway, everywhere, as a
floor — §5.4's mid-pairing fallback and any residual race deserve better than
hex. Give it **its own domain separator** (`addy-device-fingerprint-v1\0`), not
`addy-fingerprint-v1\0`: `Fingerprint()` deliberately excludes the epoch because
a head is a head, and a device phrase has different inputs and a different
meaning. Two display encodings sharing a label is the kind of reuse that is free
to avoid now and expensive to unpick later.

### E — seal each label to several epochs' profile keys

**Rejected, on two independent grounds.**

1. Roster entries are immutable and append-only, so an entry can only carry seals
   to epochs that existed *when it was written* — i.e. backwards. A backward seal
   is what hands a holder of `AK_j` the labels of devices added after epoch `j`,
   which is A's permanent-forward-leak failure with more moving parts. Sealing
   forwards would require rewriting the entry, which question 3 rules out
   outright: **any option that changes an existing entry's `label_ct` is a
   non-starter, and E in its useful direction is exactly that.**
2. It makes `label_ct` grow without bound in the number of epochs, and its length
   a function of client choice, in bytes the server stores verbatim. §5.4 forbids
   a payload in `label_ct` for `revoke` and `epoch` on the grounds that *"there is
   nothing to name, so a payload there is a covert channel."* E reopens the
   channel on the one op that still has the field.

### F — the reviewer's suggestion: carry every past `AK` in the escrow

The right instinct, one step short. Revocation is untouched (the escrow opens
only under `RK_enc`, reachable only from the phrase, so no device gains anything
and a revoked device gains nothing), the roster is untouched, and the escrow
already exists to hold precisely what is not derivable.

The step short: `AK_j` yields `K_profile_j`, which opens **epoch `j`'s
collections**, not just its labels. Today a server that hoarded epoch-3
ciphertext and later obtains the mnemonic at epoch 9 cannot read the hoard —
§9.1 step 6 deleted those objects from the honest copy, and the key is gone. Raw
F hands that hoard over. The attacker in that scenario already owns the account,
so it is not fatal; but it is a real forward-secrecy regression on *data*, paid
to recover *nicknames*, and one HKDF label buys it back.

---

## The construction, in full

### The key

One new derived key per epoch, alongside `K_profile_n` in `EpochKeys`:

```
K_label_n = HKDF-SHA256(ikm = AK_n, salt = SALT_GENESIS,
                        info = "addy-label-v1\0" || account_id || u64(n), L = 32)
```

Same shape as every other sub-key of `AK_n` (§3.2): account id and epoch
appended, one fixed salt. `K_profile_n` currently does two unrelated jobs — seal
collections, seal labels (the only two call sites are `object.go` and
`genesis.go`). This separates them, which is worth doing on its own: the key that
opens a nickname and the key that opens the vault ciphertext should not be the
same 32 bytes when one of them is about to be handed around more freely than the
other.

### The seal — unchanged

`SealLabel` / `OpenLabel` keep their AAD **byte for byte**:

```
label_ct = nonce24 || XChaCha20Poly1305(K_label_n, nonce24, label_utf8, AAD)
AAD      = "addy-label-aad-v1\0" || account_id || u64(epoch) || pub_sign
```

Only the key argument changes. **Question 5 answers itself:** the `pub_sign`
binding survives because nothing about the sealing changes — the epoch in the AAD
still names the epoch whose `K_label` opens it, and `pub_sign` still stops a label
moving between entries. Roster entries are byte-identical to today, every existing
signature stays valid, and §5.7 needs no new step.

### Where the history travels

**Escrow** (§6.1) gains one field:

```
domain      : literal     "addy-escrow-v1\0"
account_id  : fixed[16]
epoch       : u64
counter     : u64
ak_seed     : fixed[32]
label_keys  : bytes       K_label_1 .. K_label_epoch, concatenated, 32 bytes each
head_entry  : bytes
```

`label_keys` is a `bytes` field (ACE-1 has no arrays, §2.4, and this does not
need one) with a **normative length rule: `len(label_keys) == 32 * epoch`, and
`K_label_j` is at offset `32*(j-1)`.** A decoder MUST reject any other length.

That rule is what answers **question 2**. The escrow grows by 32 bytes per epoch,
and the epoch number is already in the clear in every roster entry the server
holds — so the length reveals a value the server knows exactly, and because the
verifier can *check* the length against the chain, there is no room to hide
anything in it. Fixed offsets, fixed width, no ordering freedom: no covert
channel, not merely a small one. The AAD (`account_id`, `epoch`, `counter`) and
the HPKE exporter commitment are untouched, so §6.3 and §6.6's ordering rule
stand as written.

**Handoff** (§9.3, `Handoff` in `handoff.go`) gains the same field under a
**different and deliberately narrower rule: only the label keys for epochs in
which a currently-live device was added.** A device paired at epoch `n` can then
read every *surviving* sibling's label — which closes the second half of the
finding ("a device that joins at epoch `n` … can never read the labels of its
siblings added earlier") — and cannot read the label of a device revoked before
it existed.

The two rules differ because the two channels differ in assurance, and that is
the reason to have two rules at all. The escrow opens only under `RK_enc`, so its
reader already holds the account; give it the simple, trivially checkable full
history. The handoff opens under a device's `DK_enc`, which lives in
`safeStorage` — storage §12 case 6 states is readable by anything running as the
user — so it is the low-assurance channel and gets least privilege.

Without the narrowing, every device accumulates one more label key per epoch,
forever, so the blast radius of a single compromised device grows monotonically
with the account's age and never shrinks. Each increment is small; the shape is
wrong. Under the narrowing the set shrinks as well as grows: when the last device
added in epoch `e` is revoked, `K_label_e` stops being distributed.

The set of epochs with surviving adds is computable from the chain, which the
recipient verifies (§5.7) before trusting anything in the handoff, so the
recipient **MUST** check the delivered set against that chain. Checkable, so
still no covert channel — merely checked later in the sequence than the escrow's
length rule.

**The narrowing is safe precisely because the load-bearing path does not use
it.** The §5.8 mandatory review runs on a device recovering from the mnemonic,
which reads the **escrow** and therefore the full history. The handoff serves
day-to-day display, which never needs to name a device that is gone. The one
visible cost: a device paired today shows a fingerprint rather than a name for
long-revoked devices in any history view. That is the right answer — a laptop
paired this morning has no business naming a machine retired before it existed.

**A writer MUST verify its own escrow before PUT**, as `Account.Verify()` already
does for the genesis chain and for the same stated reason: a device that somehow
holds a short list would otherwise silently truncate the history at the next
rotation, and the cheapest place to notice is the moment of writing.

### What this does to revocation — question 1, stated plainly

A device revoked at epoch `n` holds `AK_n` and `K_label_1..n`. It cannot obtain
`K_label_{n+1}`: a revocation rotation seals the new epoch individually to
surviving devices and MUST NOT chain (§9.3), and the escrow is `RK_enc`-only.

So its view of the estate freezes at its revocation, **exactly as it does today**.
It keeps the labels of devices that existed when it was live — devices whose
public keys and add-timestamps it can already read off the chain in the clear —
and learns nothing about any device added afterwards. The incremental leak versus
today is: a compromised device learns the nicknames of the user's *own* devices
that predate it. Against an attacker who already has the account's public device
list, that is marginal, and it is the price of the mandatory review working at
all. It is worth paying; A's price — every future device, forever — is not.

Summary table for question 1:

| | revoked device reads old labels | reads labels of devices added *after* its revocation |
|---|---|---|
| A | yes | **yes, forever** |
| B | yes (its own epochs) | no |
| C | yes (its own epochs) | no |
| D | unchanged | no |
| E | yes | **yes** (the only direction that helps is the leaking one) |
| **This** | yes (its own epochs) | **no** |

### Forward secrecy — question 4, for this construction

`K_label_j` opens labels and nothing else. A hoarding server that later obtains
the mnemonic gets every past nickname and **no past collection ciphertext**,
because `K_profile_j` is still only derivable from an `AK_j` that no longer
exists anywhere. That is the whole point of splitting the key: the thing that now
survives rotation is a two-word nickname, and the thing that must not survive
rotation — the data — still does not.

### Migration

The escrow plaintext gains a field, so §2.3 strictness makes an old-shaped blob
fail to decode, loudly, which is the correct behaviour. §6.8 rewrites the escrow
on every transition anyway, and there are no escrows in the field before M1
ships. This is a pre-release change or it is a much larger one.

---

## If only one thing is done

Do the key split and the escrow field. D is a good idea and costs almost nothing,
but shipping D alone would close the finding on paper while leaving the §5.8
review showing the user five words they have never seen for devices they cannot
recognise — which is the same clicked-yes as hex, in a nicer font.
