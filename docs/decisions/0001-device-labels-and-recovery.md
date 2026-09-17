# 1. Device labels, the recovery review, and what a revoked device loses

Decided 2026-09-17, after the M1 review raised "rotation orphans device labels"
and two independent reviews reached opposite conclusions about it. Both reviews
are in `docs/label-recovery-options.md` and `docs/label-recovery-ux.md`.

## The problem as it was posed

A roster `add` entry carries `label_ct`, the device's pseudonym, sealed under
`K_profile_n`. That key rotates, so after an epoch transition a device can no
longer read the labels of devices added earlier. §5.8 makes a device review the
first of four mandatory controls on a mnemonic recovery, and recovery forces a
re-key — so the review degrades exactly where it is load-bearing.

## The finding that reframed it

**A truncated chain contains no forged entries.** Every device in it was
genuinely the user's. So the review's implicit question — "do you recognise
these?" — earns a truthful *yes*, and the truthful yes is the wrong answer.
What truncation hides is a **revocation**: the sold laptop reads as live.

Recognition is therefore the wrong task. The answerable question is **"have you
got rid of any of these?"** — recall with a cue, not detection of an absence.

## Decisions

### D1. The review is a selection, not a confirmation

Devices are **revoked unless re-confirmed**, every box unchecked. Confirmed
devices are never revoked at all: they survive the rotation and receive
`AK_{n+1}` sealed to their `DK_enc`, which the recovering device does offline
because `pub_enc` is already in the chain. A sleeping laptop the user recognised
is not punished for being asleep.

This inverts the failure mode. Under bulk confirmation the lazy path — click the
green button — was the insecure one. Under selection, a device the user cannot
place is left unchecked.

It also neutralises a channel the attacker controlled: a device added by a
holder of `AK_n` arrives named whatever the attacker likes, so under
confirmation the label was simultaneously the aid and the attack. Under
selection it can only fail to persuade.

### D2. Labels stay readable across rotations — and they are load-bearing

`K_label_n = HKDF(AK_n, "addy-label-v1\0" || account_id || u64(n))`, split off
`K_profile_n`. `SealLabel` and `OpenLabel` keep their AAD byte for byte; only the
key argument changes.

The reason this matters is **not** that it makes selection nicer. It is that
without it, "leave it off when unsure" stops being a safe default and becomes the
only reachable outcome — for every device added before the current epoch, which
on any account that has rotated is most of them. Default-off is only safe when
the user can say *yes* in the cases where yes is correct.

Distribution is **asymmetric**, and the asymmetry is the point:

- The **escrow** carries the full history, fixed length `32 * epoch`, so a
  verifier checks it against the chain in one comparison and the covert channel
  closes completely rather than nearly. Its reader already holds the root key.
- The **handoff** carries only the epochs with a currently-live device. It opens
  under `DK_enc` in `safeStorage`, which the threat model says is readable by
  anything running as the user — so a full history there would make one
  compromised device's blast radius grow monotonically with account age and
  never shrink. The set shrinks as well as grows: when the last device from
  epoch `e` is revoked, `K_label_e` stops being distributed.

Safe because a revoked device holds label keys up to its own epoch and cannot
obtain `K_label_{n+1}` — exactly the position it is in today.

### D3. The card's fingerprint phrase is machine-checked

Today §5.6 describes the roster head phrase as something a human compares, which
wastes the only mechanical check in the ceremony. The recovery flow takes the
five words as input, walks the chain computing `Fingerprint(H(entry_i), acct)`,
and on no match **refuses outright** rather than falling through to a judgement
call. No card means the weaker path, labelled as such — a valid mnemonic is
never locked out.

The card gains its **print date** and loses any device names. The argument
against names is staleness rather than privacy: a genesis card lists one device,
the user later sees four, shrugs, and has been trained to dismiss a mismatch on
the one screen where dismissing one is the attack.

### D4. No five-word phrase per device

Zero recognition value — the user has never seen that form — and it dilutes the
one place the five-word form means something, which is the roster head and the
load-bearing anti-fork check. Where a label cannot be read, show short hex
*because it is ugly*, so it reads as missing data rather than as an alternative
name, with the date carrying the information: "added before your last key
change."

### D5. Not re-admitting is not the same as revoking

Treating an **absence** of assertion as strong evidence of theft is the error
that makes default-off destructive.

- **Explicitly revoked** ("I sold it", "it was stolen") — wipe on sight,
  unchanged. The user made a positive assertion about that device.
- **Not re-admitted during a recovery** — quarantine: read-only, no sync,
  blocking screen, offering *export my local data* and *pair me again* before
  anything is destroyed. Wipe on confirmation or after a grace period.

`DESIGN.md` is already most of the way here: the wipe shows "a blocking,
unmissable screen" and "does not silently delete itself out from under a live
SSH session". What is missing is only the ability to tell the two causes apart.

## Rejected

- **Re-sealing labels during rotation.** Not expensive — INCOHERENT. Changing
  `label_ct` changes the body, so the entry hash, so every subsequent
  `prev_hash`; the rebuilt chain is one every other device is *required* to
  reject as a fork, and every printed card is invalidated. The rewritten body
  would also need a signature under the key the rotation is retiring — in a
  revocation rotation, the compromised one. And the label AAD would name a
  different epoch from the entry's own field, which cannot be fixed by bumping
  that field because only an `op = epoch` entry may increment it.
- **An epoch-independent label key derived from the root.** Lets a revoked
  device read the names of devices added *after* its revocation, permanently,
  and puts never-rotating root-derived material in every device's `safeStorage`.
  The loss is the precedent of a class exempt from revocation.
- **Sealing each label to several epochs' keys.** Reopens the covert channel
  §5.4 closed.

## Two findings filed separately

### F1. The roster label is a BIRTH NAME

Renames are local, entries are immutable, and no relabel op exists. A user who
renamed `quiet-otter-41` to "work laptop" two years ago sees `quiet-otter-41` on
the recovery screen: readable, and not what they call it. **Making labels
decryptable does not make them current.**

Worse, the population that renames is plausibly the population that needs the
screen — a user with two devices never renames; a user with eight across two
sites does, and is exactly the user for whom re-pairing is expensive.

The candidate fix costs no protocol change: sync the local rename as ordinary T0
collection data keyed on `pub_sign`, leaving the roster's birth name alone. The
screen shows the current name when it has the collection and the birth name when
it does not. The open question is timing — the review runs *before* anything is
re-sealed.

`DESIGN.md` should be tightened to say which name the roster carries.

### F2. The trust-boundary guardrail has a hole

`tests/addyTrustBoundary.test.ts` is specified to pin the collection list against
`Persisted`'s key set. But `ALL_DATA_FILES` is much longer than `Persisted`, and
**every entry that is not a `Persisted` key falls outside the guardrail
entirely** — neither synced nor recorded in `NOT_SYNCED` with a reason.

Verified against the repo: 17 files in `ALL_DATA_FILES`, of which at least
`opsmaxx-runbooks.json`, `opsmaxx-processes.json`, `opsmaxx-credproxy.json`,
`opsmaxx-env-secrets.json`, `opsmaxx-ai-policy.json`,
`opsmaxx-job-approvals.jsonl` and `opsmaxx-local-sessions.jsonl` are not
`Persisted` keys.

This is the exact failure `DESIGN.md` warns about — "absence is
indistinguishable from 'I haven't added one yet'" — applied to whole FILES
rather than record types. Device-local may well be the right answer for an audit
log; nothing currently forces that decision to be made or written down.

**The guardrail must pin against `ALL_DATA_FILES` as well as `Persisted`.**

### What a revoked device actually loses, corrected

Checked against the enumerations rather than the design prose:

- **Not lost:** SSH keys referenced by path. They live outside `userData` and the
  wipe walks only `userData`, so the file survives and the synced `servers`
  record comes back pointing at it. Inline PEM is in `Persisted.servers` and
  syncs. This is the best-covered case, not a gap.
- **Destroyed with no copy anywhere:** runbooks — "whatever the user wrote down
  about their own estate" — automation rules, managed process definitions,
  backup targets, credential-proxy rules, the env-secrets registry, MCP config
  and AI policy; the command history database, local sessions, job approvals and
  both audit logs; and `external-edit/`, which may hold unsaved edits to remote
  files.
- **Regenerable but a chore:** the traffic inspector's CA, which must be
  re-minted *and* re-installed into the OS trust store by hand; RDP host trust;
  biometric enrolment; and the durable tsnet identity in `vpn-state`.

The asymmetry still points the same way — a false positive is silent, permanent
and hands over the account, while a false negative is noisy and bounded to one
device — but the margin is thin enough that D5's deferral is not optional.
