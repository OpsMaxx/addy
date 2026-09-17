# The recovery device review — human factors and cost

> Scope: the human-factors and implementation-cost half of the question. The
> cryptographic half is being judged separately; where a candidate fix has a
> confidentiality cost this document names it and hands it over rather than
> deciding it.

**Recommendation in one line: leave the crypto alone, and change what the review
asks the user to do.** The review is salvageable, but not by making the device
names readable — a review that showed perfect names would still be theatre. It
is saved by replacing "confirm this set" with "choose which of these keeps
access, default off", and by machine-checking the card's fingerprint phrase
instead of asking a human to eyeball it.

---

## 1. What the review is actually asking, and why names do not answer it

The attack is a **truncated chain**, and truncation has a property that decides
this entire question:

> Every entry in a truncated chain is authentic. The server cannot forge one. It
> can only replay a genuine prefix of the user's own history.

So the list the user is shown contains no strangers. Every device in it was
really theirs. The differences from reality are:

- devices the user **revoked** after the cut still appear;
- devices the user **added** after the cut are missing;
- the epoch transitions after the cut are missing.

That means **recognition is the wrong cognitive task**. Asking "do you recognise
`quiet-otter-41`?" gets a truthful yes, and the truthful yes is the wrong answer.
A truncated chain passes a recognition test perfectly — that is the whole shape
of the attack. Any amount of work spent making names readable is work spent
making the user better at a test the attacker was always going to pass.

The real question is not *who are these* but **is this list current**, which is a
question about time and about absence. Concretely:

**What a person in this state can do**

- Answer "have you got rid of, sold or lost a computer since March?" — episodic,
  recent, salient, and it is the single question that catches truncation.
- Compare a small integer to a small integer (2 against 3).
- Compare a date to roughly-now.
- Decide, per device, "do I want this one to keep working" — a preference, not a
  recalled fact, so stress does not degrade it.
- Type five words off a card into a box.

**What a person in this state cannot do**

- Notice that something is *missing* when nothing prompted them about it.
  Absence blindness is near-total under stress, and truncation is an absence.
- Tell an authentic-but-stale list from an authentic-and-current one by looking
  at it. There is no signal in the rows.
- Recognise a five-word phrase they have never seen (§2).
- Compare 64 hex characters. DESIGN.md already settles this.
- Hold "which of my four devices existed in March" in working memory while also
  being upset about a laptop.

**Is it theatre?** The *confirm-the-set* framing is theatre, and would remain
theatre with flawless labels, because the lazy path through it — click the green
button — is the insecure one. That is the definition. The *re-admission* framing
in §4 is not theatre, because the lazy path through it lands on the safe outcome.
The fix is to the question, not to the rendering.

---

## 2. Five-word phrases per device: no, and it does active harm

`ripple extinct closure wriggly reapprove` is not a real improvement over
`4f2a…c19b` for this task, for two reasons and one consequence.

**It carries no recognition.** The user has never seen the five-word form of that
device. The pseudonym is what the app has shown them for months; the phrase is
new text on a screen during the worst ten minutes of their year. Same information
content as hex, same zero familiarity, slightly nicer to read aloud — and reading
aloud is not the task here, because there is no second party to read it to.

**It cannot help anyway**, per §1: a per-device identifier that the user could
verify perfectly still validates a truncated chain.

**And it costs something real.** The five-word EFF phrase currently means exactly
one thing in this product: *the roster head*, the value compared between two
OpsMaxx windows, the load-bearing anti-fork control. Put six five-word phrases on
one screen and the one that matters becomes visually indistinguishable from five
that do not. That is a direct dilution of the one check DESIGN.md is most
emphatic about. Keep the form scarce so it keeps its meaning.

**Where a device's label will not open, show short hex and a sentence about
history** — hex precisely *because* it is ugly. It should look like missing data,
not like an alternative name:

> **A device added in March 2026** — added before your last key change, so its
> name cannot be read on this machine. `4f2a…c19b`

The date is doing the work; the hex is an honest "nothing here". No silent hex,
and no dressing the gap up as a name.

---

## 3. The printed card: dates yes, names no

**Do not put device names on the card.** The privacy argument is the weaker one —
the card already carries a bearer token for the whole estate, so naming the
machines adds little to a threat model where finding the card is already total
loss. The decisive argument is staleness:

> A card printed at genesis lists one device. The user restores two years later,
> sees four, concludes "the card is out of date", and shrugs. They have now been
> trained to dismiss a mismatch on this screen — and dismissing a mismatch is the
> exact behaviour the attack needs.

A check whose false-positive rate is near 100% is worse than no check, because it
teaches people to ignore the true positive when it comes.

**What the card should carry:** the head as the §5.6 **five-word phrase** (not
hex — it is for a human), the device count, and the **print date**. The date is
the cheap addition that makes the other two interpretable:

> Printed 3 February 2026 · 2 devices · `ripple extinct closure wriggly reapprove`
> Your account will have changed since this date. That is normal.

Now a difference explained by the date is not a mismatch, and a difference the
date does not explain is alarming — which is the discrimination the card exists
to support and currently cannot make.

Also offer a **reprint** when the roster changes, as a one-line dismissible
suggestion, never a nag. Free, and it keeps the anchor fresh for the people who
would actually use it.

---

## 4. The cheapest thing that makes the review real

Four changes, in priority order. The first two are the ones that matter; all four
together are a day's work against a screen that has to be built regardless.

### 4.1 Machine-check the card phrase — make the anchor an input, not a display

Today the card's head hash is described as "an out-of-band anchor for that
review", meaning a human squints at it. That wastes the one mechanical check
available in the whole ceremony.

Instead: a field on the restore screen for the five words from the card. The
client walks the served chain, computes `Fingerprint(H(entry_i), acct)` for each
entry, and looks for a match.

- **Match found** → the chain provably contains the account's state as of the
  print date. Truncation before that point is now *impossible*, not merely
  discouraged. Show the print date and continue.
- **No match** → **refuse outright.** The server is serving a chain that does not
  contain a head the user holds on paper. That is not a state an honest server
  can be in. Do not fall through to a judgement call; say what happened:
  "This server is showing a version of your device list from before [date]."
- **No card** → skip, and label the rest of the flow as the weaker,
  judgement-based path. A user with a valid mnemonic and no card must never be
  locked out.

This is the only part of the review that is a *check* rather than an opinion.
Cost: the loop is a handful of entries, `Fingerprint` already exists and is
already correct, and the comparison is string equality on five words. Call it
thirty lines plus a text field.

### 4.2 Ask for re-admission, default off — not for confirmation

§5.8 step 4 already forces a revoke-all and a fresh epoch. The review's real
output is therefore **which devices survive that rotation and receive
`AK_{n+1}`**. Present it as exactly that:

> These devices had access before. Which should keep it?

Every box unchecked by default. Precisely: **revoked unless re-confirmed.** A
confirmed device is simply never revoked — it survives the rotation and has
`AK_{n+1}` sealed to its `DK_enc` per §9.3, which the recovering device does
**offline**, because `pub_enc` is already in the chain. Confirmed devices need no
re-pairing; a sleeping laptop picks the key up when it wakes.

The resulting chain tail is exactly §9.5's hard revoke repeated, with no new ops
and no new states:

```
[revoke unconfirmed A @ n] [revoke unconfirmed B @ n] [epoch → n+1, REVOCATION_ROTATION, RK_sign] [add self @ n+1]
```

Coherent at every verifier step: epochs `n,n,n+1,n+1` increment only at the
transition (§5.7 step 6); the revokes are signed by `AK_n.sign` while the current
epoch is still `n` (step 11); the recovering device is fresh, so its `add` is not
a re-add (step 10). The worst case — confirm nothing — passes transiently through
a **zero-device set** between the last revoke and the self-add. The verifier
permits this: there is no minimum-count invariant, only `ErrEmptyChain` for a
chain with no entries (`internal/protocol/roster.go:253`). That is legal by
omission rather than by decision, so it wants a case in
`roster_adversary_test.go` pinning it deliberately.

This changes the failure mode completely:

| | Confirm-the-set | Re-admit, default off |
|---|---|---|
| A distracted user clicks through | every stale device is re-admitted | nothing is re-admitted |
| Cost of being wrong | silent, permanent, invisible | a wipe and a re-pair — see below |
| Unreadable label | blocks a correctness judgement | see §4.2.1 — this is the catch |

The asymmetry is the point, but the cheap side is **not** cheap, and an earlier
draft of this document was wrong to call it "a thirty-second re-pair". An
unconfirmed device wakes, reads the roster, sees itself revoked and **wipes its
local state** — and the wipe (`ALL_DATA_FILES` / `ALL_DATA_DIRS`,
`src/main/services/backup.ts:364`, `:428`) is far wider than the synced
collection list. Sorted by what actually happens:

| | Fate |
|---|---|
| Device keys (`opsmaxx-secrets.json`) | Destroyed — correctly; that is what revocation means |
| `Persisted` collections + vault, env, knownHosts | Come back from sync; the vault locked behind its master password |
| SSH keys referenced by `keyPath` | **Never left.** They live outside `userData`, the wipe only walks `userData`, and the synced `servers` record points at the same path. Net loss zero |
| Inspector CA, RDP host trust, biometric enrolment, `vpn-state` tsnet identity | Lost, regenerable — but the CA means re-installing into the OS trust store by hand |
| Runbooks, automation rules, managed processes, backup targets, credproxy rules, env-secrets registry, MCP config, AI policy | **Lost and unreproducible.** None is a `Persisted` key, so none is in a synced collection |
| Command history, local sessions, job approvals, credproxy audit, AI audit | **Lost and unreproducible** — append-only history by definition |
| `external-edit/` | Remote file contents, possibly holding unsaved edits |

The last three rows are the problem. `opsmaxx-runbooks.json` is "whatever the
user wrote down about their own estate", it is not synced, and a mistaken
exclusion destroys it with no copy anywhere.

**This does not overturn default-off, but it makes the deferral below mandatory
rather than a nicety.** Compromise still beats data loss — a false positive is
silent, permanent and hands an attacker the account, while a false negative is
noisy, bounded to one device and, with §4.2.2, recoverable. But the margin is thin
enough that shipping default-off *without* deferral would not be defensible.

**No lockout.** The user holds the mnemonic and is a live device in the new
epoch. No path through this screen locks them out; the cost is data loss, which
is a different and smaller thing.

> **Finding, beyond this document's scope but worth filing.** The guardrail in
> `tests/addyTrustBoundary.test.ts` pins the collection list against
> `Persisted`'s key set. Every file in `ALL_DATA_FILES` that is *not* a
> `Persisted` key — runbooks, rules, processes, targets, credproxy, MCP, AI
> policy, the history DB, the four audit logs — is therefore outside the
> guardrail entirely: neither synced nor recorded in `NOT_SYNCED` with a reason.
> That is exactly the "absence is indistinguishable from 'I haven't added one
> yet'" failure `DESIGN.md` warns about, applied to whole files instead of record
> types. Device-local may well be the right answer for audit logs; the point is
> that nothing forces the decision to be made or written down.

#### 4.2.2 Defer the wipe when the cause is non-re-admission

An explicit revoke and a non-re-admission are different evidence and deserve
different handling:

- **Explicitly revoked** ("I sold it", "it was stolen") — wipe on sight, as
  today. The user made a positive assertion about that device.
- **Not re-admitted during a recovery** — **quarantine, do not wipe.** Go
  read-only, stop syncing, show the blocking screen, and offer *export my local
  data* and *pair me again* before anything is deleted. Wipe on confirmation, or
  after a grace period.

Treating an *absence* of assertion as strong evidence of theft is the error that
makes default-off destructive. "I didn't recognise the name" and "that laptop was
stolen" must not produce the same outcome.

The security cost of deferring is close to nil, and `DESIGN.md` already concedes
why: the wipe "does not reach a machine that never comes online again", and
full-disk encryption is the control that matters. The wipe only helps against an
attacker who boots the machine, lets it reach the network, and has not already
copied the disk — while having had physical possession throughout. That is a thin
case to weigh against destroying an honest user's runbooks.

Most of this already exists: `DESIGN.md` specifies a blocking, unmissable screen
and says the device "does not silently delete itself out from under a live SSH
session", so the wipe is already gated on a human. What is missing is the ability
to tell the two causes apart. §5.2 of `PROTOCOL.md` reserves the unused flag bits
and requires verifiers to reject unknown ones, so a third bit —
`0x04 NOT_READMITTED`, set on revokes authored during a recovery ceremony — is
the anticipated kind of change: inside the signed body, so the server can neither
strip nor forge it. Roughly fifteen lines, a verifier rule and a test.

**Order matters:** §4.1 runs first and can hard-fail. Never offer a re-admission
list for a chain you already know is forged.

#### 4.2.1 Why this makes readable labels necessary rather than optional

This is the correction to the first draft of this document, and it comes from the
crypto review's side of the question arriving at the opposite conclusion.

Default-off is a *per-device choice*, not a bulk confirmation. A choice needs
something to choose on. The first draft argued that a user who cannot identify a
device should leave it off, and that the label therefore does not matter. That is
right about the security of any single row and wrong about the system, because of
the cost above:

> If labels are unreadable for **every** device added before the current epoch —
> which is every long-lived device on any account that has ever rotated — then
> "leave it off when unsure" is not a safe default. It is the only reachable
> outcome, and it wipes the user's entire estate.

Default-off is safe only when the user can say *yes* in the cases where yes is
correct. Strip that ability and the default stops being a default. So readable
labels are load-bearing under this design in a way they never were under
confirm-the-set — not to make confirmation work, but to make **selection** work,
and to stop the safe default from being a destructive one.

Note the affected population is not marginal and overlaps exactly with the
devices that matter: an account reaches epoch 2+ through a theft, a sale, a
hygiene rotation or a previous recovery, all of which are moments when the device
set has churned and selection is hardest.

**One discount on the benefit, stated because it is easy to miss.** The roster
label is a **birth name**. Renames are local (`DESIGN.md:346`), entries are
immutable, and no relabel op exists — mechanically, a rename cannot reach the
roster today. So a user who renamed `quiet-otter-41` to "work laptop" two years
ago will see `quiet-otter-41` on this screen: a readable name they have not used
in two years. Making labels decryptable does not make them current. This does not
overturn the case for readable labels — most devices are never renamed — but it
does mean the ceiling is lower than "the name the app has shown them for months",
and `DESIGN.md:346`'s wording should be tightened to say which name the roster
carries. If cross-device renames ever become a requirement, that is a third
reason to revisit the T0-collection option in §5.

### 4.3 Lead with the date of the last change

One sentence above the list:

> Your device list was last changed on **14 March 2026** — six months ago.

`ts` is inside the signed body, so a truncating server cannot alter it and cannot
forge a fresher one. The error is **one-directional**: the displayed date can
only ever be too old, never too new. The tell therefore always points at the
attack, which is what makes this worth showing rather than decoration. It is also
the most answerable sentence on the screen — a person knows roughly when they
last touched their machines.

Implementation note: `protocol.Device` (`internal/protocol/roster.go:176`) carries
`Epoch` but not `TS`. Plumb `TS` through from the entry; it is already parsed.

### 4.4 Ask the negative directly

> Have you removed, sold or lost a device since then? **Yes / No**

Yes → stop, and explain why: if a revoked device is showing in this list, the
server is serving an old copy. This is the one question that targets truncation
head-on, and it is a recall-a-specific-event question, which people are good at,
rather than a spot-the-absence question, which they are not.

### 4.5 Count against the card — keep, do not build for

Once §4.1 is in place the count is cryptographically redundant: the head phrase
commits to the entire chain, count included. Keep the count on the card and on
the screen because it is legible and reassuring, but do not spend engineering on
it as a control. It is already free.

### 4.6 The user who kept the phrase but not the card

The population that misses §4.1 is larger than "never printed a card". The print
dialog opens at setup and the second-device gate forces possession of **the
phrase** — but not of the card. The realistic common case is *twelve words in a
password manager, card in a drawer or never printed*: recovery works perfectly
and the head anchor is gone.

For that user what remains is §4.3, §4.4, and — doing nearly all of the work —
§4.2's default. The honest statement is not "nothing is left"; it is that **the
only mechanical check is gone, the two judgement checks are weak, and the safe
default is carrying the load.** That inverts the ordering above on *coverage*:
§4.1 is the only real check but protects a minority, while §4.2 protects
everyone. §5.8 of `PROTOCOL.md` should say which control covers which population
rather than listing four controls as though each applied to every user.

**One cheap win that shrinks this population.** Most people who kept the phrase
kept it by pasting it into a password manager. Make the copy-to-clipboard handler
emit the five-word head phrase and the date alongside the twelve words. It is a
string concatenation, it converts the common case into a card-equivalent case,
and it exposes nothing new — the head phrase is already on screen and on the
card, and it would sit beside something strictly more powerful. It goes stale
exactly as the card does, so it re-offers on roster change, like the reprint in
§3.

---

## 5. Cost-to-benefit of the candidate fixes

No users, no shipped versions, no migration burden — so this is purely "what is
the cheapest correct thing", with no legacy discount for leaving it alone.

**There are three candidates, not four.** "Re-seal every label on rotation" is not
a design; see §5.4.

**Revised bottom line: do both the presentation fix and the label-key split.** The
first draft of this document said presentation alone was sufficient. That was
wrong, and §4.2.1 is why: default-off re-admission needs the user to be *able* to
say yes, and unreadable labels turn the safe default into a universal wipe. The
two fixes are orthogonal and both load-bearing:

- **Presentation** makes the review *real* — without it, perfectly readable names
  still produce a confident yes on a truncated chain.
- **Readable labels** make the review *usable* — without them, the only reachable
  outcome destroys the estate's unsynced local state.

Ordering if only one could ship: presentation still first, because unreadable
labels fail *noisily* to recoverable data loss while confirm-the-set fails
*silently* to a compromised account. But nothing forces that choice here.

### 5.1 Presentation fix — do it

Zero protocol change. Zero churn in `roster_adversary_test.go`, `roster.go`,
`genesis.go` or `keys.go`. The restore screen has to be built either way; §4 is
the difference between building it well and building it badly, and costs about a
day.

### 5.2 Per-epoch `K_label_n`, carried in escrow and handoff — do it

This is the crypto review's proposal and it is better than the epoch-independent
key this document originally weighed (§5.3). Split `K_label_n` off `K_profile_n`,
and carry `K_label_1..n` in the escrow blob and the epoch handoff. A recovering
device opens escrow, gets every label key, and reads every label.

Two properties that earn it:

- **No confidentiality regression at all.** A revoked device holds label keys up
  to epoch `n` and cannot obtain `K_label_{n+1}`, exactly as today. §5.3 could
  not say this.
- **It avoids a forward-secrecy trap this document did not spot.** Escrowing raw
  `AK` history would let a server that hoarded epoch-3 collection ciphertext and
  later obtained the mnemonic read the hoard — forward secrecy traded for
  nicknames. Splitting the key confines the escrowed history to labels, and the
  labels are *generated pseudonyms*, so the history it exposes has no semantic
  content. The narrowness of the key is what makes carrying its history safe.

**Cost is more than the twenty lines §5.3 claimed, and less than option 5.5.**
`keys.go` gains a `derive32` and a field; `SealLabel`/`OpenLabel` take `kLabel`.
The real work is that the escrow plaintext (§6.1) stops being a fixed-width
`ak_seed` and gains a variable-length key list — a wire-format change to the
object with the most normative language in the protocol — plus the same in
`handoff.go`, plus regenerating the pinned test vectors. Call it a focused day
and a half across `keys.go`, `genesis.go`, `escrow.go`, `handoff.go` and their
vectors. Affordable, pre-users, and it buys a screen the user can actually act
on. Escrow growth is 32 bytes per epoch — irrelevant.

### 5.3 Epoch-independent label key — superseded, do not do

One `derive32`, pin the epoch in the label AAD, adjust seal/open. Genuinely
twenty lines, and it solves the display symptom.

But a label key that never rotates is a key a revoked device keeps forever, so a
revoked laptop keeps reading the names of every device added *after* it was
revoked. That is a confidentiality regression the epoch mechanism exists
precisely to prevent. §5.2 achieves the same display outcome with no such cost,
for about a day more work. Take §5.2.

### 5.4 Re-seal every label on rotation — incoherent, not expensive

There is no expensive version of this that works, and it is worth writing down
why so it stops being proposed. Four independent walls, any one fatal:

1. **Chain linkage.** Changing `label_ct` changes `body`, hence `H(entry_i)`
   (which covers `body || sig`, §5.5), hence every subsequent `prev_hash`. The
   chain must be rebuilt from *i* onward, producing a new head — so every other
   device, holding a pin, is *required* to reject it as a fork under §5.7 step 12
   (`ErrForked`). It does not merely cost work; it produces a chain honest
   devices must refuse. Every printed card is invalidated too.
2. **Signature.** A rewritten body needs a new signature, verified under
   `AK_{entry.epoch}.sign` (§5.7 step 8) — the key the rotation is retiring, and
   in a `REVOCATION_ROTATION` the compromised one. The re-sealed chain would be
   authenticated by the key the rotation exists to escape.
3. **Label AAD.** `AAD = … || u64(epoch) || pub_sign`. Sealing under
   `K_profile_{n+1}` puts `n+1` in the AAD while the entry's own `epoch` says `n`.
4. **Epoch monotonicity.** Bumping the entry's `epoch` to fix (3) is refused by
   §5.7 step 6, which permits an increment only at an `op = epoch` entry.

The only escape is to move the bytes out of the immutable entry into a separate
mutable object — which is §5.5 under another name. The `relabel`-op salvage is
not re-sealing either: it is an append-only log of labels living inside the
roster, with chain growth of O(devices × rotations), a new verifier rule, and a
per-device disclosure of when each rotation happened.

### 5.5 Labels in a T0 collection — not now, but keep it on the shelf

The cleanest design here, and probably what one would draw from scratch: a
`devices` collection sealed to `K_profile_n`, re-sealed automatically by §9.1
step 2, so rotation stops being special. It touches §5.4, §5.7 step 10, §9 and
genesis, needs a conflict story for concurrent renames, and removes the
`pub_sign`-in-AAD binding as a *chain* property. Roughly a week in the most
security-critical code in the repo.

§5.2 buys the same display outcome for a fraction of the cost, so it wins today.
But §5.5 is the only option that also makes **renames propagate** — see §4.2.1,
where the roster's birth-name problem survives every other fix on this list. If
cross-device renames become a requirement, this is the answer; do not build it
for labels alone.

---

## 6. Summary

| Question | Answer |
|---|---|
| Is the review salvageable? | Yes, but only by changing the question. Confirm-the-set is theatre at any rendering quality; re-admit-default-off is not. |
| Five-word phrase per device? | No. No recognition value, cannot catch truncation, and dilutes the one phrase that matters. Use short hex — it should read as missing data. |
| Names on the card? | No — it goes stale and trains people to dismiss mismatches. Add the **print date** instead, and render the head as words. |
| Cheapest real fix? | Machine-check the card phrase (hard-fail on absence); re-admission defaulting to off; last-changed date in words; "have you removed a device?" |
| Crypto change worth it? | **Yes — `K_label_n` split, carried in escrow and handoff (§5.2).** Not for readability's sake, but because default-off selection is unusable without it. |

Two sentences carry the whole document. **A review that displayed every device's
name perfectly would still hand a truncated chain a confident yes** — so the
presentation fix is the one that addresses the defect. And **a selection screen
nobody can select on is not a safe default, it is a wipe** — so the label fix is
what makes the presentation fix survive contact with a rotated account. Neither
is sufficient alone, and together they are about two and a half days.
