# addy protocol — v1 (M1 spine)

**Status: normative for M1. Written 2026-09-17 against `docs/DESIGN.md` and
`THREAT_MODEL.md`, before any crypto code exists.** The design says "written
protocol spec with test vectors, before code" and "M1 is the gate"; this is that
document. Where `DESIGN.md` left something open, this file closes it and says so
— every such decision is listed in §14 rather than buried where a reviewer has
to find it.

Two independent implementations (Go on the server and the client daemon,
TypeScript in the OpsMaxx renderer) must interoperate byte for byte. Everything
below is therefore stated as bytes, not as intent. Test vectors that a Go test
consumes directly are in `internal/protocol/testdata/vectors.json`; §13 says what
is in it and how it was generated.

`MUST`, `MUST NOT`, `MAY` are RFC 2119.

---

## 1. Cipher suite, pinned

| Role | Algorithm | Codepoint / library |
|---|---|---|
| Hash | SHA-256 | — |
| KDF | HKDF-SHA256 (RFC 5869) | — |
| Signature | Ed25519 (RFC 8032), pure, no prehash, no context | — |
| Key agreement | X25519 (RFC 7748) | — |
| Public-key encryption | HPKE base mode (RFC 9180) | KEM `0x0020` DHKEM(X25519, HKDF-SHA256), KDF `0x0001` HKDF-SHA256, AEAD `0x0003` ChaCha20-Poly1305 |
| Symmetric encryption | XChaCha20-Poly1305, 24-byte nonce | — |
| PAKE | SPAKE2 over Ed25519, `salsa.debian.org/vasudev/gospake2`, vendored | — |
| Mnemonic | BIP39, 12 words, English wordlist, **empty passphrase** | — |

**XChaCha20-Poly1305, not ChaCha20-Poly1305, for anything addy nonces itself.**
A 12-byte nonce needs a per-key counter, and two devices writing the same
collection under the same `K_profile_n` cannot coordinate one. A 24-byte random
nonce needs no coordination and no state. HPKE's internal AEAD keeps its own
sequence number and is not affected.

**Ed25519 verification MUST reject non-canonical encodings and MUST NOT accept
small-order public keys.** Go's `crypto/ed25519` already does the former; a
verifier that accepts a small-order `pub_sign` in a roster entry would accept a
device nobody holds a key for.

---

## 2. ACE-1 — the canonical serialisation

Everything signed, hashed or used as AAD is encoded with **ACE-1** (addy
canonical encoding, version 1). It is not JSON, and this is the point: JSON has
more than one encoding of the same document, which invites signing over one and
verifying over another. ACE-1 has exactly one encoding of a given field list, so
"re-serialise and compare" is a valid implementation of "did this verify".

### 2.1 Primitives

| Type | Encoding |
|---|---|
| `u8` | one byte |
| `u32` | 4 bytes, **big-endian** |
| `u64` | 8 bytes, **big-endian** |
| `fixed[N]` | exactly N raw bytes, **no length prefix** — the width is pinned by the field's declaration |
| `bytes` | `u32` length, then that many raw bytes |
| `string` | UTF-8, **NFC-normalised**, no BOM, then encoded exactly as `bytes` |
| `bool` | `u8`, `0x00` or `0x01` |
| `enum` | `u8` drawn from a closed table declared with the field |
| `optional<T>` | `u8` presence tag: `0x00` and nothing follows, or `0x01` followed by `T` |

Big-endian throughout because every wire format this talks to (HPKE, TLS,
WebSocket framing) already is, and one endianness is one fewer thing to get
wrong at 3am.

### 2.2 Structures

A structure is the concatenation of a **domain prefix** followed by its fields
in the fixed order given in this document. There is no field count, no tag, no
map and no self-description: the field list *is* the schema, and it lives here.

A domain prefix is ASCII followed by a single `0x00`, e.g. `addy-roster-v1\0`
is the 15 bytes `61 64 64 79 2d 72 6f 73 74 65 72 2d 76 31 00`. The trailing NUL
is part of the prefix and MUST be present. Two structures never share a prefix,
so a byte string valid under one is not valid under another — that is what makes
a signature over one purpose useless against another.

### 2.3 Decoder strictness

A decoder **MUST** reject, with no partial result:

1. trailing bytes after the last declared field;
2. a length prefix larger than the bytes remaining;
3. a `bool` that is not `0x00` or `0x01`;
4. an `enum` value not in its declared table;
5. an `optional` presence tag that is not `0x00` or `0x01`;
6. a `string` that is not well-formed UTF-8, or is not in NFC;
7. a domain prefix that is not the expected one.

Every one of these is a place where a lenient decoder and a strict one would
disagree about what was signed. Accepting trailing bytes alone is enough to let a
malicious server append a second, attacker-chosen entry to a signed body and have
half the fleet see it.

### 2.4 What is *not* in ACE-1

No maps, no variable-typed arrays, no floating point, no timestamps-as-strings,
no nested self-describing values. If a future field needs one of those, it gets a
new domain prefix and a new version, not a relaxation here.

### 2.5 Versioning

A structure's version lives in its domain prefix and nowhere else. `addy-roster-v2\0`
is a different structure from `addy-roster-v1\0`; there is no version field to
strip, downgrade, or disagree about. An implementation that does not know a
prefix refuses the object rather than guessing.

### 2.6 Timestamps

Every `ts` in this document is **milliseconds since the Unix epoch, UTC, `u64`**.
`ts` is **display only**. It is never used for ordering, expiry or validity —
ordering is `seq`, and validity is signatures. A clock is a thing an attacker
controls on a machine they own; nothing load-bearing may depend on one.

### 2.7 Worked byte-level example

Structure `addy-ace-demo-v1` (this structure exists only to pin the encoding;
it carries no protocol meaning):

```
domain  : literal            "addy-ace-demo-v1\0"
a       : u8                 1
b       : u32                42
c       : u64                0x0123456789abcdef
d       : bytes              "addy"
e       : string             "quiet-otter-41"
f       : optional<bytes>    absent
g       : optional<bytes>    present, 0xdead
h       : fixed[4]           f0 f1 f2 f3
```

encodes to 68 bytes:

```
616464792d6163652d64656d6f2d7631 00      domain "addy-ace-demo-v1" || 0x00
01                                        a  = 1
0000002a                                  b  = 42
0123456789abcdef                          c
00000004 61646479                         d  = len 4, "addy"
0000000e 71756965742d6f747465722d3431     e  = len 14, "quiet-otter-41"
00                                        f  = absent
01 00000002 dead                          g  = present, len 2, 0xdead
f0f1f2f3                                  h  = 4 raw bytes
```

Flat:

```
616464792d6163652d64656d6f2d763100010000002a0123456789abcdef0000
0004616464790000000e71756965742d6f747465722d34310001000000 02dead
f0f1f2f3
```

Note `d` and `e` encode identically for identical bytes — the distinction
between `bytes` and `string` is a *validation* rule (UTF-8, NFC), not an encoding
one. Note also `f`'s absence costs exactly one byte and cannot be confused with a
present-but-empty value, which encodes as `01 00000000`.

---

## 3. Key hierarchy

```
BIP39 12 words (128 bits entropy)      the ONLY thing a user must keep
  │  PBKDF2-HMAC-SHA512, 2048 iters, salt "mnemonic", empty passphrase
  ▼
seed (64 bytes)
  │  HKDF-SHA256, salt = SALT_GENESIS
  ├─ info "addy-root-sign-v1\0"  ─► RK_sign  Ed25519 seed  (32 bytes)
  └─ info "addy-root-enc-v1\0"   ─► RK_enc   X25519 scalar (32 bytes)

AK_n — 32 random bytes from the CSPRNG. NOT derived. Rotatable.
  │  HKDF-SHA256, salt = SALT_GENESIS
  ├─ info "addy-epoch-sign-v1\0" || account_id || u64(n) ─► AK_n.sign  Ed25519 seed
  ├─ info "addy-epoch-enc-v1\0"  || account_id || u64(n) ─► AK_n.enc   X25519 scalar
  └─ info "addy-profile-v1\0"    || account_id || u64(n) ─► K_profile_n (32 bytes)

DK_sign  Ed25519 seed  ─┐ 32 bytes each, two INDEPENDENT CSPRNG draws,
DK_enc   X25519 scalar ─┘ generated on the device, never transmitted
```

### 3.1 Constants

| Name | Value | Bytes |
|---|---|---|
| `SALT_GENESIS` | ASCII `addy-genesis-v1` | `616464792d67656e657369732d7631` (15) |
| BIP39 PBKDF2 salt | ASCII `mnemonic` (the BIP39 standard salt, empty passphrase appended) | — |

`SALT_GENESIS` is the HKDF salt for **every** derivation in this document.
HKDF's salt is a domain separator, not a secret, so one fixed value is correct
and a per-account one would only create a second thing to get wrong.

### 3.2 Info labels, in full

Every `info` is `<ascii label> || 0x00` and, for everything below the root,
`|| account_id (16 bytes) || u64(epoch)`.

| Derived key | IKM | info (ASCII part) | account id + epoch appended? |
|---|---|---|---|
| `RK_sign` seed | BIP39 seed | `addy-root-sign-v1` | **no** |
| `RK_enc` scalar | BIP39 seed | `addy-root-enc-v1` | **no** |
| `AK_n.sign` seed | `AK_n` | `addy-epoch-sign-v1` | yes |
| `AK_n.enc` scalar | `AK_n` | `addy-epoch-enc-v1` | yes |
| `K_profile_n` | `AK_n` | `addy-profile-v1` | yes |

**The root labels carry no account id, and that is deliberate, not an
oversight.** `account_id` is derived *from* `RK_sign`'s public half (§3.4), so
mixing it into `RK_sign`'s own derivation is circular. Everything below the root
carries both, which is what `DESIGN.md` asks for — the account id binds a
derivation to this account and the epoch binds it to this rotation, so a key from
one epoch cannot be replayed as a key from another.

### 3.3 Ed25519 seeds and X25519 scalars are never the same bytes

`RK_sign`'s Ed25519 seed and `RK_enc`'s X25519 scalar are two separate HKDF
outputs under two different info labels, and likewise `AK_n.sign` and `AK_n.enc`.
No implementation may reuse one output for both, and no implementation may
convert an Ed25519 key to an X25519 key (birational maps between the curves exist
and are exactly the shortcut this rule forbids). Signing and key-agreement keys
that share bytes make every cross-protocol attack on Ed25519/X25519 live in a
system that otherwise has none.

`internal/protocol` asserts `RK_sign.seed != RK_enc.scalar` and the same for
every epoch, as a test, because it is a one-character mistake to make and an
invisible one to spot.

### 3.4 Account id

```
account_id = SHA-256("addy-account-id-v1\0" || RK_sign.pub)[0:16]
```

16 bytes, displayed as 32 lowercase hex. It is a function of the root key alone,
so it is stable across every epoch — an epoch transition changes the epoch and
nothing else (§9), and a changing account id would break every object name.

It is **not a secret**: the server holds it, it is in every object path, and the
threat model already concedes the server knows which account is which. It is a
name, not a capability.

### 3.5 Epoch numbering

Epochs start at **1**. `0` is never a valid epoch, so a zeroed or absent field
cannot be mistaken for a legitimate one.

### 3.6 Device keys

`DK_sign` and `DK_enc` are two independent 32-byte draws from the platform
CSPRNG, made on the device, at pairing time. They are **not** derived from
`AK_n`, from the mnemonic, or from each other — a device key derivable from the
account key would make every device's identity recoverable by anyone holding the
mnemonic, which is the opposite of the pseudonym property `DESIGN.md` commits to.

Nothing host-derived enters either draw: no hostname, no OS username, no MAC
address, no serial, no `machine-id`. A device wiped and re-paired mints new keys
and is a new device to everyone.

---

## 4. The four signature purposes

`DK_sign` signs three different kinds of thing and `AK_n.sign` / `RK_sign` sign a
fourth. As originally drafted the same device key signed both a login challenge
the *server* chose and a request authorization — a chosen-message oracle across
two purposes. The fix is structural, not procedural:

1. Every signature is over an **ACE-1 structure with its own domain prefix.** A
   signature over `addy-login-v1\0…` cannot verify against
   `addy-authz-v1\0…` because the first bytes differ, so a valid signature for
   one purpose is worthless for another.
2. Every signature covers a **client-contributed nonce**: 32 bytes from the
   signing device's CSPRNG, fresh per signature. The server never chooses all of
   the bytes that get signed.

The four prefixes are `addy-login-v1\0`, `addy-authz-v1\0`,
`addy-roster-v1\0` and `addy-signal-v1\0`. `DESIGN.md` names
`addy-roster-v1\0` explicitly; the other three follow its pattern.

### 4.1 Login — signed by `DK_sign`

```
domain          : literal     "addy-login-v1\0"
account_id      : fixed[16]
device_nonce    : fixed[32]   CSPRNG, this device, this login
server_nonce    : fixed[32]   the server's challenge
server_spki     : fixed[32]   SHA-256 of the instance's TLS SubjectPublicKeyInfo
ts              : u64
```

`server_spki` is the TOFU pin from the `addy://` join string. Without it a
login signature captured from one instance is replayable against another
instance that presents the same account — the signature says "I am this device",
not "I am this device *talking to you*".

The server MUST check `server_spki` against its own key: it accepts a login only
if `server_spki` is SHA-256 of the DER SubjectPublicKeyInfo of a certificate it
has itself presented, in a handshake, for the TLS server name the login arrived
on, and answers anything else exactly as it answers a bad signature. Without
that comparison the binding binds nothing — somebody terminating TLS for the
hostname with any certificate the device accepts could forward the login and
keep the session. It follows that **a TLS-terminating proxy in front of addy is
unsupported**: the device would sign the proxy's key, and the relay refuses it.
Pass TLS through (SNI routing, TCP proxying) instead.

The server MUST reject a login whose `server_nonce` it did not issue, whose
`account_id` is not the one the presented `DK_sign` belongs to, or which reuses a
`server_nonce` already spent.

"Belongs to" is read off the stored chain: the server folds it into its device
set without verifying signatures (it holds no epoch key), and accepts a roster
append only from a device in that set.

A key the chain revoked is answered, once its signature verifies, `403` with
`{"error":"this device was removed from the account","roster":{"chain":"<base64>"}}`
— the `roster` object exactly as `GET /v1/roster` returns it. A revoked device
learns of its revocation from the chain (§9.5), and must verify that chain with
its own pinned keys before acting on it: a client that wiped on the server's
word would hand the server the power to wipe any device.

A key the chain has never named gets a session reaching only `GET /v1/roster`,
`GET /v1/obj/escrow` and a `POST /v1/roster` whose entry is an `add` of that
same key signed by `RK_sign`, because a device recovering from the mnemonic
mints fresh keys and must read the chain before it can add itself. The server
can verify that one signature, holding `RK_sign`'s public half from
registration, and once the add is stored the session is a member's.

A `revoke` cuts every live session of the device it names down to
`GET /v1/roster`.

### 4.2 Request authorization — signed by `DK_sign`

```
domain          : literal     "addy-authz-v1\0"
account_id      : fixed[16]
device_nonce    : fixed[32]
method          : string      e.g. "PUT"
path            : string      e.g. "/v1/obj/servers"
body_hash       : fixed[32]   SHA-256 of the request body; 32 zero bytes if there is none
ts              : u64
```

Binding method, path and body means an authorization for a `GET` cannot be
replayed as the `DELETE` the server would rather have.

### 4.3 Roster entry — signed by `AK_n.sign` or `RK_sign`

The roster entry body of §5.1. Its client-contributed nonce is the explicit
`nonce` field. `prev_hash` is not sufficient on its own: the server chooses which
chain it serves, so it has partial control over `prev_hash`, and "the server
cannot choose all the signed bytes" has to be true unconditionally.

### 4.4 Signalling — signed by `DK_sign`

```
domain            : literal     "addy-signal-v1\0"
account_id        : fixed[16]
epoch             : u64
device_nonce      : fixed[32]
peer_nonce        : fixed[32]   the peer's nonce from the offer this answers (zero on an offer)
peer_pub_sign     : fixed[32]   the peer's DK_sign public half
dtls_fingerprint  : fixed[32]   SHA-256 of the local DTLS certificate
roster_head       : fixed[32]   the signer's current roster head hash
ts                : u64
```

A peer MUST reject a signalling message whose signer is not an `add`-ed,
un-`revoke`-d device in the roster it has verified, and MUST reject a DTLS
handshake whose certificate fingerprint is not the one in the signed blob.
Without the fingerprint inside the signature a malicious relay simply substitutes
its own and reads the clipboard, the files and everything else on the data
channel — the relay does not need to break any crypto, it just needs the
fingerprint to be unsigned.

`roster_head` lets each peer notice immediately that the other is on a different
view of the roster, which is what a forked chain looks like from the inside.

---

## 5. The roster chain

An append-only hash-chained log. Every client verifies it from genesis before it
encrypts anything to any device in it.

### 5.1 Entry body — `addy-roster-v1\0`

```
domain      : literal     "addy-roster-v1\0"
account_id  : fixed[16]
epoch       : u64         the epoch this entry belongs to
seq         : u64         0 for genesis, +1 per entry, no gaps
prev_hash   : fixed[32]   hash of the previous entry; 32 zero bytes at genesis
op          : enum u8     0x01 add | 0x02 revoke | 0x03 epoch
signer      : enum u8     0x01 AK.sign | 0x02 RK_sign
flags       : u8          bitfield, see 5.2
nonce       : fixed[32]   CSPRNG, the author's
pub_sign    : fixed[32]   see 5.3 — meaning depends on op
pub_enc     : fixed[32]   see 5.3
label_ct    : bytes       see 5.4
ts          : u64         display only
```

The **entry** on the wire is `body || sig`, where `sig` is the 64-byte Ed25519
signature over `body`. The split is unambiguous without a length prefix because
`sig` is fixed-width and last.

### 5.2 Flags

| Bit | Name | Meaning |
|---|---|---|
| `0x01` | `MNEMONIC_AUTHORED` | this entry was authored during a mnemonic-recovery ceremony |
| `0x02` | `REVOCATION_ROTATION` | `op = epoch` only: this rotation is a response to compromise, not hygiene |

All other bits MUST be zero and a verifier MUST reject a non-zero unknown bit —
an ignored bit is a covert channel and a future compatibility trap at the same
time.

`MNEMONIC_AUTHORED` is **inside the signed body**, so the server cannot strip it
to hide the fact. A verifier additionally treats any `op = add` entry with
`signer = RK_sign` as mnemonic-authored whether or not the flag is set, because
`RK_sign` only exists where the phrase was typed. Either condition raises the
loud, separate "a device was added using the recovery phrase" notification on
every other device.

### 5.3 What `pub_sign` / `pub_enc` mean per op

| `op` | `pub_sign` | `pub_enc` | Signed by |
|---|---|---|---|
| `0x01 add` | the device's `DK_sign` public half | the device's `DK_enc` public half | `AK_n.sign` (normal), or `RK_sign` (recovery) |
| `0x02 revoke` | the revoked device's `DK_sign`, exactly as in its `add` | the revoked device's `DK_enc`, exactly as in its `add` | `AK_n.sign` |
| `0x03 epoch` | `AK_{epoch}.sign` public half | `AK_{epoch}.enc` public half | `RK_sign` if `REVOCATION_ROTATION`, else `AK_{epoch-1}.sign` |

For `op = epoch` the entry's `epoch` field is the **new** epoch. A hygiene
rotation is therefore verified under the key of the epoch *before* the one it
names; this is stated rather than inferred, because getting it off by one
produces a chain that verifies on the author's machine and nowhere else.

### 5.4 `label_ct`

For `op = add`, the device's pseudonym sealed to `K_profile_n`:

```
label_ct = nonce24 || XChaCha20Poly1305(K_profile_n, nonce24, label_utf8, AAD)
AAD      = "addy-label-aad-v1\0" || account_id || u64(epoch) || pub_sign
```

`pub_sign` in the AAD binds the label to the device it names, so two labels
cannot be swapped between two entries by an attacker who cannot decrypt either.

For `op = revoke` and `op = epoch`, `label_ct` MUST be **zero length**, and a
verifier MUST reject a non-empty one. There is nothing to name, so a payload
there is a covert channel.

The signature covers the ciphertext, so the server can store and serve entries it
cannot read and cannot forge — it does not need to understand an entry to hold
it. A device that is mid-pairing does not yet hold `K_profile_n` and falls back
to displaying the `pub_sign` fingerprint; this is the one place where a roster
notification names a key rather than a device.

### 5.5 Entry hash and the chain

```
H(entry) = SHA-256("addy-roster-link-v1\0" || body || sig)
```

**The hash covers the signature, not just the body.** A hash over the body alone
would let an attacker who can produce a second valid signature over the same body
(Ed25519 signatures are not unique unless verified strictly) substitute it
without changing any subsequent `prev_hash` — the chain would still link and the
head hash a human compares between two windows would still match. Covering `sig`
makes the head hash a commitment to the exact bytes, which is the only version of
that check worth showing to a person.

- `entry[0].prev_hash` = 32 zero bytes.
- `entry[i].prev_hash` = `H(entry[i-1])` for `i > 0`.
- **roster head hash** = `H(last entry)`. This is the value shown in the UI, on
  the printed card, and compared between two OpsMaxx windows — never read from
  the portal and never from `addy status`, because both are software the
  attacker controls.

### 5.6 The roster head as words

Hex is not compared by humans; they check the first four characters and the last
four, which is most of the way to not checking at all. The head is therefore
displayed as **five words from the vendored EFF long wordlist** (7776 entries),
derived:

```
okm  = HKDF-SHA256(salt = SALT_GENESIS, ikm = roster_head, info = "addy-fingerprint-v1\0" || account_id, L = 10)
w_j  = be_uint16(okm[2j:2j+2]) mod 7776,  j = 0..4
```

`mod 7776` on a 16-bit value has a bias under 2^-9 per word, which does not
matter: this is a display encoding for human comparison, not a key. The
derivation is ours — Bitwarden documents that its fingerprint phrase is five EFF
words but deliberately does not publish the selection function, so there is
nothing to copy. One wordlist, vendored, shared by the Go and TypeScript sides,
pinned identical by a test; a phrase that differs between the two windows being
compared is worse than no phrase.

### 5.7 Verification algorithm

Given a serialised chain and, optionally, a pinned `(seq, hash)` the client has
seen before, a client MUST perform every step in order and abort at the first
failure. There is no partial acceptance and no "warn and continue".

1. **Parse.** Split the byte stream into entries. Each entry's body MUST decode
   under §2.3 strictness; reject the whole chain otherwise. Reject an empty chain.
2. **Genesis.** `entry[0].seq == 0`, `entry[0].prev_hash == 0^32`,
   `entry[0].op == add`, `entry[0].epoch == 1`. A genesis entry that is a revoke
   or an epoch transition describes an account that never existed.
3. **Account binding.** Every entry's `account_id` equals the expected one, and
   equals `SHA-256("addy-account-id-v1\0" || RK_sign.pub)[0:16]` for the
   `RK_sign.pub` this client holds or was given out of band. Reject a chain that
   is internally consistent but belongs to somebody else.
4. **Sequence.** `entry[i].seq == i` for all `i`. No gaps, no repeats, no
   reordering.
5. **Link.** `entry[i].prev_hash == H(entry[i-1])` for `i > 0`, with `H` as §5.5.
6. **Epoch monotonicity.** `entry[i].epoch >= entry[i-1].epoch`, and
   `entry[i].epoch > entry[i-1].epoch` **only** when `entry[i].op == epoch`, in
   which case the increment is exactly 1. An epoch that moves without a
   transition entry, or skips a number, is a fork.
7. **Flags.** Unknown bits zero. `REVOCATION_ROTATION` set implies
   `op == epoch`. `op == epoch` with `REVOCATION_ROTATION` implies
   `signer == RK_sign`; a revocation rotation signed by `AK_n.sign` MUST be
   refused, because the whole point is that the compromised epoch key does not
   authorise the escape from itself.
8. **Signer selection.** Verify `sig` over `body` under:
   - `signer == RK_sign` → the account's `RK_sign` public half, which is fixed
     at genesis and known to the client.
   - `signer == AK.sign` and `op != epoch` → `AK_{entry.epoch}.sign`.
   - `signer == AK.sign` and `op == epoch` → `AK_{entry.epoch - 1}.sign`.

   The `AK_n.sign` public half for each epoch comes from that epoch's transition
   entry, which has already been verified by the time it is needed, because the
   chain is processed in order. `AK_1.sign` comes from the genesis ceremony and
   is pinned alongside `RK_sign` — see §10.
9. **Signature.** Ed25519 verify. Reject small-order and non-canonical
   `pub_sign`. A failure here ends the chain; do not skip the entry.
10. **Op semantics.**
    - `add`: `pub_sign` MUST NOT already be present as an un-revoked device.
      Re-adding a live device is either a bug or an attempt to change its
      `pub_enc`.
    - `revoke`: `pub_sign` MUST name a currently-present device, and `pub_enc`
      MUST byte-equal that device's `pub_enc` from its `add`. A revoke naming a
      substituted `pub_enc` is refused.
    - `epoch`: `pub_sign` and `pub_enc` become `AK_{epoch}`'s public halves for
      the remainder of the chain.
    - `label_ct` empty for `revoke` and `epoch`, non-empty for `add`.
11. **Revoked devices cannot author.** For any entry signed by `AK_n.sign`, the
    current epoch at that point in the chain MUST be `n`. A device revoked in
    epoch `n` still holds `AK_n` and can produce entries that verify under it —
    which is why the revocation of a possibly-hostile device is always
    accompanied by a rotation to `n+1` (§9). Once the chain has advanced past
    `n`, an entry claiming `epoch == n` at a `seq` after the transition fails
    step 6, and an entry claiming `epoch == n+1` signed by `AK_n.sign` fails
    step 8.
12. **Rollback.** If the client holds a pin `(seq_pinned, hash_pinned)`:
    - the chain MUST contain an entry at `seq_pinned` whose `H` equals
      `hash_pinned` — otherwise the server has forked the chain;
    - `last.seq >= seq_pinned` — otherwise the server has rewound it.
    If the client holds **no** pin (a mnemonic restore), it MUST NOT accept the
    chain silently. It goes to §5.8.
13. **Adopt.** Compute the head hash, update the pin to `(last.seq, head)`, and
    only now encrypt anything to any device in the resulting device set.

### 5.8 A client with no pin

A device restored from the mnemonic alone has no history, so steps 12's rollback
checks have nothing to compare against and a malicious server can serve a
truncated chain from before a revocation. There is no cryptographic fix — the
truncated chain is genuinely, validly signed. The controls are therefore
procedural and all four are mandatory:

1. **Mandatory device review.** The user is shown every device in the chain, with
   its label and its fingerprint, and MUST confirm the set before any collection
   is re-sealed. A restore is the one moment where a human is guaranteed present.
2. **The printed card carries the roster head hash and the device count at print
   time.** A user who kept the card has an out-of-band anchor for that review.
3. **The escrow blob carries the signed roster head entry and a monotonic
   counter** (§6), so an old escrow is detectable rather than invisible. A chain
   whose head is *behind* the escrow's head entry MUST be refused outright — the
   server has served an escrow newer than the chain it also serves, and that is
   not a state an honest server can be in.
4. **Recovery forces a hard re-key before anything syncs.** A fresh epoch and a
   revoke-all, on the reasoning that a recovery is by definition a moment when
   the user no longer knows which devices are theirs.

---

## 6. The escrow blob

The escrow blob exists because **`AK_n` is random and cannot be derived from the
mnemonic.** Everything else the mnemonic needs it can compute. Putting derivable
material in escrow would hand the server a second chain to choose between; the
blob holds exactly what is not derivable, plus the two things that make serving
an old copy detectable.

### 6.1 Plaintext — `addy-escrow-v1\0`

```
domain      : literal     "addy-escrow-v1\0"
account_id  : fixed[16]
epoch       : u64
counter     : u64         monotonic, +1 per escrow write, starts at 1
ak_seed     : fixed[32]   AK_epoch, the 32 random bytes
head_entry  : bytes       the roster head entry, body || sig, verbatim
```

`head_entry` is the whole entry rather than just its hash, so a recovering device
can verify the head's signature itself instead of taking the server's word for
where the chain ends. The head hash is `H(head_entry)` by §5.5.

### 6.2 AAD — `addy-escrow-aad-v1\0`

```
domain      : literal     "addy-escrow-aad-v1\0"
account_id  : fixed[16]
epoch       : u64
counter     : u64
```

The epoch is in the AAD of this and every other sealed object in the system
(§7), so a blob from epoch `n` cannot be presented as one from epoch `n+1`.

### 6.3 Seal

HPKE base mode, suite as §1, recipient `RK_enc`'s public half:

```
info   = "addy-escrow-hpke-v1\0" || account_id || u64(epoch)
enc, ctx = HPKE.SetupBaseS(RK_enc.pub, info)
ct     = ctx.Seal(aad, plaintext)
commit = ctx.Export("addy-escrow-commit-v1\0" || account_id || u64(epoch) || u64(counter), 32)
```

### 6.4 Object — `addy-escrow-obj-v1\0`

```
domain      : literal     "addy-escrow-obj-v1\0"
suite       : enum u8     0x01 = the suite pinned in §1; any other value is refused
enc         : bytes       the HPKE encapsulated key, 32 bytes for X25519
commit      : fixed[32]
ct          : bytes
```

### 6.5 Why a commitment, and why this one

ChaCha20-Poly1305 is not key-committing: a ciphertext can be constructed that
decrypts successfully under two different keys, to two different plaintexts.
HPKE inherits that. It matters here more than anywhere else in the system:
recovery is a person typing twelve words from a printed card into a machine,
against a server that chooses which blob to serve. A wrong key must fail loudly.
Plausible garbage that parses as an `AK_n` would have the user re-seal the whole
estate under a key an attacker chose.

**The commitment is the HPKE exporter, checked before the AEAD.** The exporter
secret is derived from the KEM shared secret, the `info` string and the mode, so
the 32-byte tag commits to the recipient key, the account, the epoch and the
counter in one value. The two alternatives `DESIGN.md` offers are both weaker
here: "hash the key into the AAD" cannot reach HPKE's AEAD key, which is internal
to the context and never exposed; encrypt-then-MAC would mean a second key
schedule and a second key to derive, manage and get wrong. The exporter is part of
RFC 9180, is present in both CIRCL and Go 1.26's `crypto/hpke`, and costs one
HKDF-Expand.

### 6.6 Open — order is normative

1. Decode the object under §2.3 strictness. Reject an unknown `suite`.
2. `HPKE.SetupBaseR(enc, RK_enc, info)`.
3. Compute the exporter tag and compare it to `commit` **in constant time**.
4. **Only if it matches**, call `ctx.Open(aad, ct)`.
5. Decode the plaintext. `account_id`, `epoch` and `counter` MUST equal the ones
   in the AAD — they are in both places so that a mismatch means tampering rather
   than a convention.
6. `counter` MUST be `>=` the highest counter this client has seen for this
   account. A lower one is the server serving an old escrow; refuse.
7. Verify `head_entry`'s signature and check the served chain's head against it
   per §5.8 step 3.

An implementation that opens first and checks the commitment afterwards is
**non-conforming**. The point is to fail before a chosen ciphertext produces any
plaintext at all, not to notice afterwards.

### 6.7 The second door

`AK_n` is additionally sealed to one optional recovery recipient — another age
key, a hardware token, or a passkey. It is the **same plaintext and the same
AAD**, sealed under a second HPKE recipient and stored as a second object. Two
independent losses instead of one; without it there is exactly one door and it is
made of paper.

### 6.8 When escrow is written

On genesis, and on **every** epoch transition, before the transition entry is
appended (§9). The counter increments on every write. An escrow whose `epoch` is
behind the roster's current epoch is stale by definition and a client that finds
one MUST treat the account as mid-transition and re-read the chain rather than
use the `AK` it found.

---

## 7. Sealed collection objects

Every T0 collection is one object, sealed to `K_profile_n`.

### 7.1 Plaintext — `addy-coll-v1\0`

```
domain          : literal     "addy-coll-v1\0"
schema          : u32         the document schema version
writer_version  : string      the OpsMaxx version that wrote it, e.g. "0.48.0"
counter         : u64         monotonic per collection, +1 per write
payload         : bytes       the collection's own serialisation
```

`schema` and `writer_version` are **inside the ciphertext** because the server
must not be able to read or forge them, and `counter` is inside for the same
reason: it is the anti-rollback control and an attacker who could edit it would
have no control to defeat. A client below a document's `schema` goes read-only
for that collection and says "update OpsMaxx to sync this", rather than
round-tripping the document through a typed parser that silently drops the fields
it does not know.

### 7.2 AAD — `addy-obj-aad-v1\0`

```
domain      : literal     "addy-obj-aad-v1\0"
account_id  : fixed[16]
epoch       : u64
collection  : string      e.g. "servers"
```

The collection name in the AAD stops the server serving the `vault` ciphertext in
answer to a request for `servers`; the epoch stops it serving last epoch's.

### 7.3 Object — `addy-obj-v1\0`

```
domain      : literal     "addy-obj-v1\0"
suite       : enum u8     0x01 = XChaCha20-Poly1305
nonce       : fixed[24]   CSPRNG, fresh per write
ct          : bytes
```

The vault is sealed exactly like every other collection and its payload is
`opsmaxx-vault.json` **verbatim** — already ciphertext under the user's master
password. Nothing in the sync path ever opens it, so `locked`, `secured` and
`open` are all irrelevant to sync, and the mnemonic is not a skeleton key for it.

---

## 8. Pairing

### 8.1 The code

Format: `NN-word-word`, e.g. `42-inkwell-flatfoot`.

| Component | Draw | Entropy |
|---|---|---|
| `NN` | uniform `0..99`, rendered with a leading zero | 6.64 bits |
| `word` ×2 | uniform, independent, **with replacement**, from a vendored 256-word list | 8.00 bits each |
| | | **22.64 bits total** |

The 256-word list lives at `internal/pairing/words.txt`, is vendored once and
shared by the Go and TypeScript sides, and is pinned identical by a test —
exactly as the device-name and EFF wordlists are. Words are lowercase ASCII,
4–9 letters, no two within edit distance 1 of each other, so a misheard code
fails as a wrong code rather than as a different valid one.

22.64 bits is only a defence if somebody trustworthy counts the guesses; see
§8.6.

Normalisation before any use: NFC, lowercase, ASCII hyphen `U+002D` as the only
separator, no surrounding whitespace. Both sides normalise; a code that differs
only in case must not produce a different password.

### 8.2 Code to PAKE password

```
pw = SHA-256("addy-pake-pw-v1\0" || len_u32(code) || code || pairing_id)
```

`pairing_id` is 16 CSPRNG bytes chosen by the initiating device and carried in
the clear on the signalling channel — it names the session, it is not a secret.
Binding it into the password means a code observed in one session cannot be
replayed into another.

`account_id` is deliberately **not** in the password: the joining device does not
know it yet, and learns it from the pairing. A binding to a value one side cannot
compute is not a binding, it is a bug.

### 8.3 The exchange

> **Correction, 2026-09-17, found by implementing it.** The frame table below
> puts A's `DK_sign.pub` on frame 3 and `conf_B` on frame 2, and §8.4 puts BOTH
> signing keys in the confirmation label. Those cannot both hold: B computes
> `conf_B` for frame 2, and at that point it has not been told A's key.
>
> Resolved by moving **A's `DK_sign.pub` to frame 1**, which is the smaller
> change and costs nothing — it is a public key, the relay sees it either way,
> and the roster carries device public keys as T1 metadata regardless. Frame 3
> then carries only `conf_A`: that value already binds A's key, so a relay that
> substituted it fails the confirmation rather than needing a second copy to be
> compared against.
>
> The implementation in `internal/pair` follows the corrected shape.
>
> **Also corrected:** §8.4 says `K` is "the SPAKE2 shared secret as `gospake2`
> returns it". `gospake2` is not used — see the SPAKE2 correction at the top of
> `DESIGN.md` and `docs/spake2-review.md`. `K` is SHA-256 of RFC 9382's
> length-prefixed transcript, which binds both identity strings, both messages,
> the group element and the password scalar.


SPAKE2 with asymmetric roles. `A` = the initiating device (the one showing the
code), `B` = the joining device (the one typing it). Identity strings are the
fixed ASCII `addy-pair-init` and `addy-pair-join`; they are constants, not
device identifiers, because the devices have no shared names yet.

Three frames, two of which carry PAKE material. They travel over the
**pairing rendezvous**, `/v1/pair/{pairing_id}?as=initiator|joiner` (§11.1),
not over `/v1/signal`: the joiner has no session and does not know the
account id, so it cannot use an authenticated route. It is a long poll, not a
WebSocket. Each role `POST`s `{"frame": base64}` into the other's mailbox (204)
and `GET`s its own (200 with a frame, or 204 when the poll window passes empty):

| # | Frame | From | Carries |
|---|---|---|---|
| 1 | `pair.start` | A | `pairing_id`, `spake2_msg_A` |
| 2 | `pair.reply` | B | `spake2_msg_B`, `conf_B`, B's `DK_sign.pub`, B's `DK_enc.pub` |
| 3 | `pair.confirm` | A | `conf_A`, A's `DK_sign.pub` |

B can compute the shared secret on receiving frame 1, so its key confirmation
rides along with its PAKE message. The server relays all three and learns nothing
from any of them.

### 8.4 Key confirmation

```
okm    = HKDF-SHA256(salt = <none>, ikm = K, info = "addy-pair-confirm-v1\0" || pairing_id || A.DK_sign.pub || B.DK_sign.pub, L = 64)
conf_A = okm[0:32]
conf_B = okm[32:64]
```

`K` is the SPAKE2 shared secret as `gospake2` returns it. Both comparisons are
constant-time. A verifies `conf_B` on frame 2; B verifies `conf_A` on frame 3.
Either failure aborts the pairing, burns the code and counts an attempt.

The identity keys are in the `info` string, so the confirmation binds the PAKE
result to the two keys the devices are about to trust. Without that binding the
PAKE proves a shared password and nothing about who holds it.

### 8.5 SAS

Matrix's construction, copied rather than invented, because a homegrown SAS
encoding is a bug waiting to bias the output.

```
sas = HKDF-SHA256(salt = <none>, ikm = K, info = "addy-sas-v1\0" || pairing_id || A.DK_sign.pub || B.DK_sign.pub, L = 6)
```

**No salt** — not an all-zero salt string, but HKDF-Extract's salt omitted, which
HKDF defines as `HashLen` zero bytes. This matches Matrix exactly; an
implementation that passes `SALT_GENESIS` here produces different emoji on one
side and a false MITM alarm.

Six bytes, first 42 bits, seven groups of six, most significant bit first:

```
i0 = sas[0] >> 2
i1 = (sas[0] & 0x03) << 4 | sas[1] >> 4
i2 = (sas[1] & 0x0f) << 2 | sas[2] >> 6
i3 =  sas[2] & 0x3f
i4 =  sas[3] >> 2
i5 = (sas[3] & 0x03) << 4 | sas[4] >> 4
i6 = (sas[4] & 0x0f) << 2 | sas[5] >> 6
```

Equivalently, with `V` the 48-bit big-endian integer of the six bytes:
`i_j = (V >> (48 - 6(j+1))) & 0x3f`. The last six bits of `sas[5]` are unused.
Both formulations are asserted equal in the vector generator, because they are
the two ways implementers write this and they must not diverge.

Each index selects from the vendored Matrix `sas-emoji.json`, 64 entries, indices
0–63. Vendored, never fetched: a pairing check that needs the network is not a
pairing check.

**The SAS is displayed only after key confirmation verifies.** Not before, not
alongside. Seven emoji beside one green Confirm button is a formality, not a
control; the mismatch path gets equal visual weight and default focus, which is
the lesson Matrix learned the hard way.

**SPAKE2 is the MITM defence; the emoji are a tripwire.** A completed PAKE cannot
produce mismatched SAS, so the emoji do not defeat a malicious relay — SPAKE2
already did. They catch an implementation error or a downgrade that the PAKE
alone would not surface. That labelling decides what the adversary test tests:
case 5 in §12 is "an injected transcript fault produces mismatched SAS ⇒ abort
**before** `AK_n` is sealed", which is testable, and not "a PAKE peer that fails
the SAS", which was not.

### 8.6 The attempt limiter runs on the initiating device

A is the only party with an interest in counting. The relay has none — letting it
count hands the attacker its own rate limit, and this is a regression from code
that already got it right (`cliPairing.ts:78-93` counts in the device's own main
process).

- **5 failed attempts** for a code, counted by A as failures of `conf_B`.
- **60 second TTL** from display.
- On either limit A burns the code, discards `pairing_id`, and the UI offers a
  new one.
- Three distinct messages, never one: wrong code, expired code, locked out for N
  minutes.

The adversary test runs **with the server's limiter disabled**, because a server
that does not limit is the real condition this defends against.

### 8.7 On confirm

> **Correction, 2026-09-17, found by implementing it.** This section says the
> handoff plaintext is "the `addy-escrow-v1\0` structure" with a different HPKE
> info label. §10.1 says the joining device "receives `RK_sign.pub` in the same
> sealed structure". The escrow structure has no field for it, so both cannot
> hold.
>
> Resolved with a structure of its own, `addy-handoff-v1\0`, carrying the escrow
> fields plus `rk_sign_pub` — rather than by adding an optional field to the
> escrow. Two structures that differ by a field and share a domain prefix are two
> structures a verifier can be confused between; two with different prefixes are
> not, and there is a test that neither opens as the other.
>
> `RK_sign.pub` has to travel because a joining device verifies the chain from
> genesis, and step 8 of that algorithm needs the root key to check root-signed
> entries. It cannot take that key from the server: a chain verified against a
> key the server supplied is not verified.
>
> `OpenHandoff` additionally refuses a handoff whose `rk_sign_pub` does not
> derive the `account_id` it claims — otherwise a device could be handed a
> valid-looking handoff for a different account and would go on to verify that
> account's chain quite happily.


A, and only after both confirmations and the human's SAS confirmation:

1. HPKE-seals `AK_n` to B's `DK_enc` — plaintext `addy-escrow-v1\0` structure
   with `counter` set to A's current escrow counter, info
   `"addy-handoff-hpke-v1\0" || account_id || u64(n)`, same exporter commitment
   discipline as §6;
2. appends an `op = add` roster entry for B, signed by `AK_n.sign`;
3. PUTs the updated chain.

Nothing is sealed to B before the human confirms. That ordering is the whole
value of the confirmation step.

---

## 9. Epoch transitions

An epoch transition **changes the epoch and nothing else.** It does not add a
device, does not remove one, does not change the account id, and does not alter
any collection's contents. Anything that also needs to happen is a separate,
separately signed entry. A combined operation is one where a verifier has to
decide which half it is checking, and that decision is where the hole goes.

### 9.1 Order of operations — normative

1. Mint `AK_{n+1}` from the CSPRNG. Derive `AK_{n+1}.sign`, `.enc`,
   `K_profile_{n+1}`.
2. Re-seal **every** T0 collection under `K_profile_{n+1}` and PUT each under its
   epoch `n+1` object name. Epoch `n` objects stay where they are.
3. Write the escrow blob for epoch `n+1`, counter `+1`.
4. Seal `AK_{n+1}` to each surviving device's `DK_enc` (see §9.3).
5. **Now** append the `op = epoch` roster entry and PUT the chain.
6. **Only then** delete the epoch `n` objects.

Re-seal first, transition second, delete third. Any other order has a window in
which a device that reads the chain finds an epoch whose objects do not exist
yet, or in which a crash leaves the account with neither epoch's data readable. A
crash between any two steps leaves the account usable at epoch `n`, which is the
only acceptable failure mode.

### 9.2 Who may sign

| Rotation | `flags` | `signer` | Reachable from |
|---|---|---|---|
| Hygiene | `REVOCATION_ROTATION` clear | `AK_n.sign` | any paired device |
| Revocation | `REVOCATION_ROTATION` set | **`RK_sign`** | the mnemonic only |

A revocation rotation signed by `AK_n.sign` MUST be refused (§5.7 step 7). The
compromised epoch key does not get to authorise the escape from itself: a device
that holds `AK_n` and is about to be revoked could otherwise sign its own
"rotation" to an `AK_{n+1}` it chose.

### 9.3 Chaining `AK_{n+1}` under `AK_n`

- A **hygiene** rotation **MAY** publish an `epoch-handoff` object: `AK_{n+1}`
  sealed under `AK_n.enc`, so devices catch up without re-pairing.
- A **revocation** rotation **MUST NOT**. Chaining would let the revoked device,
  which still holds `AK_n`, follow the rotation straight through and decrypt
  epoch `n+1` — which is the exact thing the rotation exists to prevent. In a
  revocation rotation `AK_{n+1}` is sealed individually to each **surviving**
  device's `DK_enc`, and to nothing else.

An implementation MUST refuse to read an `epoch-handoff` object for an epoch
whose transition entry has `REVOCATION_ROTATION` set, even if the server serves
one. The rule has to be enforced by the reader as well as the writer, because the
writer is not always honest.

### 9.4 What rotation does not undo

Anything the attacker already fetched and decrypted before revocation. Rotation
protects the future, never the past. A revoked device also keeps `AK_n` and
everything it already downloaded, and a revoked device that never comes online
again is never wiped — for that machine full-disk encryption is the control that
matters. Both sentences belong at the button, not only here.

### 9.5 Soft revoke

A `op = revoke` entry signed by `AK_n.sign`, with **no** epoch transition.
Honest devices stop encrypting to the removed device and the server stops serving
it. It does **not** stop a malicious holder of `AK_n` re-admitting itself, and
the UI says exactly that at the button, because a soft revoke a user believes is
a hard one is worse than no revoke at all. Anything phrased as theft, loss or
compromise routes to the hard path and asks for the phrase.

A hard revoke is two entries: the `revoke` in epoch `n`, then the `epoch`
transition to `n+1`. Revoke first, so the reason is recorded in the epoch the
device was actually in.

---

## 10. Genesis

Identity is **client-asserted**. The server validates nothing about who you are;
it stores a public key it has never seen and cannot vouch for. That is the point.

Entirely offline, in this order:

1. Generate 128 bits of entropy from the CSPRNG; encode as 12 BIP39 words.
2. Derive the BIP39 seed (empty passphrase), then `RK_sign` and `RK_enc` (§3).
3. `account_id = SHA-256("addy-account-id-v1\0" || RK_sign.pub)[0:16]`.
4. Mint `AK_1` from the CSPRNG; derive `AK_1.sign`, `AK_1.enc`, `K_profile_1`.
5. Generate `DK_sign` and `DK_enc` for this device — two independent draws.
6. Author roster entry `seq = 0`: `op = add`, `epoch = 1`, `prev_hash = 0^32`,
   `signer = AK.sign`, this device's public halves, its sealed label. Sign with
   `AK_1.sign`.
7. Build the escrow blob at `counter = 1` with that entry as `head_entry`, seal
   to `RK_enc`.
8. Open the print dialog for the recovery card. It carries the twelve words, the
   roster head hash and the device count at print time. It is a **printable
   card, not a file** — a `.txt` in `~/Downloads` holding the keys to the estate
   is the product committing its own worst ick on day one.
9. *Then* register with the server: present `RK_sign.pub`, `AK_1.sign.pub`, the
   genesis entry and the escrow blob, and spend an invite token.

### 10.1 Where `RK_sign.pub` and `AK_1.sign.pub` are pinned

§5.7 step 8 needs `RK_sign.pub` to verify `RK_sign`-signed entries and
`AK_1.sign.pub` to verify genesis, and it cannot take either from the server. A
client gets them:

- **at genesis**, from its own derivation;
- **at pairing**, inside the HPKE-sealed handoff from an already-trusted device —
  the joining device receives `AK_n` and therefore derives `AK_n.sign.pub`
  itself, and receives `RK_sign.pub` in the same sealed structure;
- **at recovery**, by deriving `RK_sign` from the mnemonic and taking
  `AK_n.sign.pub` from the escrow blob's `ak_seed`.

At no point does a client learn either key from an unauthenticated server
response. A chain is verified against keys the client already held, or it is not
verified.

### 10.2 What genesis deliberately lacks

No password reset, no email verification, no account recovery, no
organisation-level recovery and there will not be one — it is a deliberate
backdoor and the exact inverse of the roster's premise. There is no account
password anywhere in this document; the T2 public profile is readable by an
authenticated device of the account and nothing else.

The mnemonic is **a bearer token for the whole estate minus the vault** —
unhardened, un-rate-limited, usable by anyone holding it from anywhere. The card
says that in those words. Calling it a "recovery phrase" invites the mental model
of an account-recovery email, which is the wrong one and leads people to store it
accordingly.

Verification of the phrase gates **the second device**, not first launch. Nobody
writes down a phrase while evaluating software they have used for ninety seconds;
gating first launch trains people to screenshot it.

---

## 11. Object names

```
/v1/obj/{account_id}/e{epoch}/{collection}          sealed collection, §7
/v1/obj/{account_id}/escrow/{counter}               escrow blob, §6
/v1/obj/{account_id}/escrow-alt/{counter}           second door, §6.7
/v1/obj/{account_id}/handoff/e{epoch}               epoch-handoff, hygiene only, §9.3
/v1/roster/{account_id}                             the chain, §5
```

The epoch is in the path **and** in the AAD of the object it names. The path is
the server's; the AAD is the client's. Only one of them is trustworthy, and the
other exists so a mismatch is loud.

### 11.1 The HTTP calls, and the statuses a client acts on

The relay's routes live in `internal/api/api.go`; this lists the ones whose
contract a client has to agree with. On the wire an object is addressed as
`/v1/obj/{name}?epoch=N` within the session's own account, which the server
takes from the session and never from the path.

Every request MAY carry `X-Addy-Protocol: addy-protocol-v1` (the value of
`protocol.ProtocolVersion`). A relay answers **426** to a request whose header
names a different version, before any handler runs. A request with no header is
let through, because OpsMaxx 0.58 shipped without sending one. `GET /v1/meta`
reports `{"version", "build", "protocol"}`.

| Call | Answers |
|---|---|
| `GET /v1/signal` | Waits for a frame in this device's own mailbox: 200 `{"frame"}`, or 204 when the poll window passes. A `GET` with a body is refused with 400. |
| `POST /v1/signal?to={peer DK_sign hex}` | Body `{"frame": base64}`, into that peer's mailbox in the same account: 204. |
| `DELETE /v1/obj/{name}[?epoch=N]` | 204, or 404 when there is nothing to delete. Without `epoch`, every epoch of the name goes. Frees the quota the object held. |
| `POST`/`GET /v1/pair/{pairing_id}?as=…` | Unauthenticated, §8.3. **404** means this relay has no pairing with that id: it finished, expired, or the relay restarted, since the rendezvous is held in memory. The device should say "start again" rather than keep polling. Only the initiator's first `POST` creates a pairing. A `GET` for an unknown id waits out one poll window before answering 404, so a joiner that arrives a moment early is not refused. |
| any authenticated call | **413** when the body is over 8 MiB. The relay reads one byte past the limit and refuses; it never truncates. Before this, a truncated body failed its request signature and came back as a misleading 401. |

All errors are JSON `{"error": "…"}`.

---

## 12. Adversary cases, as protocol assertions

The seven cases `DESIGN.md` lists, restated as precisely what must be refused and
by which rule. `internal/roster/adversary_test.go` implements these against a
deliberately malicious server harness; `tests/addyRoster.test.ts` implements the
client-side half.

**1. A roster entry the epoch key did not sign.**
*Refused by* §5.7 step 8–9. The verifier selects the signing key from the entry's
own `signer` and `epoch` fields and verifies; there is no path that accepts an
entry on the server's say-so. *Why it matters:* this is the assertion behind the
headline claim. The server holds the chain and no signing key, so it cannot
author an entry at all.

**2. A chain whose `prev_hash` does not link.**
*Refused by* §5.7 step 5. `H` covers `body || sig`, so a link check is a check on
the exact bytes, not on a re-serialisation of them. *Why it matters:* without it
the server can splice entries from two different histories into one chain that
verifies entry-by-entry.

**3. A chain rewound to a lower `seq` than the client has seen.**
*Refused by* §5.7 step 12, using the client's pin. The client also refuses a
chain that does not contain its pinned hash at its pinned `seq`, which catches a
fork that is *longer* rather than shorter. *Why it matters:* a rewound chain hides
a revocation, and a hidden revocation means honest devices keep encrypting to a
device the user removed.

**4. A real device's entry with a substituted `pub_enc`.**
*Refused by* §5.7 step 9 — `pub_enc` is inside the signed body. For a `revoke`,
additionally by step 10, which requires byte-equality with the `add`. *Why it
matters:* this is the attack that needs no key at all. Swap the encryption key
in a device's entry and every honest device seals the next epoch to the attacker
while the roster still reads correctly to a human.

**5. An injected transcript fault produces mismatched SAS ⇒ abort before `AK_n`
is sealed.**
*Refused by* §8.4 and §8.7. Key confirmation is verified before the SAS is shown,
the human confirms after, and the `AK_n` seal happens only after both. *Why it
matters:* the emoji are a tripwire for implementation faults and downgrades, not
the MITM defence — SPAKE2 is that — and the ordering is what makes the tripwire
mean anything. Note what this is *not*: a completed PAKE cannot produce
mismatched SAS, so "a PAKE peer that fails the SAS comparison" is not a testable
case.

**6. A revoked device signing a valid new entry.**
*Refused by* §5.7 steps 6, 7 and 11, once the epoch has advanced. The revoked
device holds `AK_n` and can produce entries that verify under `AK_n.sign` — so
the defence is not the signature, it is that `AK_n.sign` is no longer the key for
any epoch at or after the transition, and a revocation rotation is `RK_sign`-only
so `AK_n` cannot authorise its own successor. *Why it matters:* this is the
reason the epoch exists. Without it a stolen laptop is a permanent, unrevocable
account compromise, because `safeStorage` is readable by anything running as the
user.

**7. A truncated chain served to a client with no pin.**
*Refused or escalated by* §5.8. Cryptographically the truncated chain is valid,
so the controls are the mandatory device review, the printed card's head hash and
device count, the escrow's monotonic counter and signed head entry, and the
forced hard re-key before anything syncs. A chain whose head is behind the
escrow's `head_entry` is refused outright — no honest server can be in that
state. *Why it matters:* it is the one case where the pin-based defence is simply
absent, and the original adversary list tested rollback against a client that
already had a pin, which is the case that already worked.

Three more that follow from this document and belong in the same harness:

**8. A cross-purpose signature.** A `DK_sign` signature produced for
`addy-login-v1\0` MUST NOT verify against an `addy-authz-v1\0` structure. The
domain prefixes differ in the first bytes, so this holds by construction; the
test asserts it anyway, because "by construction" is a claim about code someone
has yet to write. Vector `signature_purposes` carries both, and the verifier in
§13 checks the negative.

**9. An escrow blob under the wrong key.** MUST fail at the commitment check
(§6.6 step 3), before `Open` is called. The negative vector flips one bit of
`commit`; an implementation that opens first and checks after passes the
functional test and fails this one.

**10. A revocation rotation with an `epoch-handoff` object.** MUST be refused by
the reader (§9.3), not merely not written. A server that keeps the handoff object
from a previous hygiene rotation and serves it against a revocation rotation
would otherwise walk a revoked device into the new epoch.

---

## 13. Test vectors

`internal/protocol/testdata/vectors.json`. Every value in it was **computed, not
invented**: generated by a Go program using `crypto/ed25519`, `crypto/hkdf`,
`crypto/pbkdf2`, `crypto/ecdh`, `github.com/cloudflare/circl/hpke` and
`golang.org/x/crypto/chacha20poly1305`, then re-verified by a second program that
reads only the JSON and re-derives every value from the hex. That verifier is the
shape `internal/protocol/vectors_test.go` should take.

> **Every private key in that file is a fixed test value.** They are `00 01 02 …`
> style constants precisely so that nobody mistakes one for real key material.
> The mnemonic is the all-zero-entropy BIP39 phrase. None of it may ever appear
> outside a test.

> **Known inconsistency, 2026-09-17.** The pairing vector's code is
> `42-inkwell-flatfoot`, which is `DESIGN.md`'s illustrative example. Neither
> word is in the shipped 256-word list (`internal/pair/wordlists/codewords.txt`),
> so `pair.NormaliseCode` refuses it and a test driving this vector through the
> real code path would fail. The list is right and the example is not:
> "flatfoot" is slang for a police officer, which fails the list's own rule that
> a word must be innocuous. The vector is regenerated with a real code when the
> pairing exchange is implemented; recorded here rather than silently patched,
> because the derived PAKE password and SAS depend on the code and must be
> recomputed together.

### 13.1 Shape

```
{
  "_meta":              { spec, version, generator, warning },
  "root":               { bip39 entropy/mnemonic/seed, hkdf salt,
                          rk_sign {info,seed,pub}, rk_enc {info,scalar,pub},
                          account_id },
  "epoch_keys":         [ { epoch, ak_seed,
                            ak_sign {info,seed,pub}, ak_enc {info,scalar,pub},
                            k_profile {info,key} } ],          // epochs 1 and 2
  "devices":            { "A": {...}, "B": {...} },            // labels + DK keys
  "canonical_encoding": { fields[] with per-field hex, encoded_hex, sha256 },
  "roster_chain":       { account_id, label_nonces,
                          entries[] { note, epoch, seq, op, signer, flags,
                                      prev_hash, nonce, pub_sign, pub_enc,
                                      label_ct, ts_ms,
                                      body_hex, sig_hex, entry_hash_hex,
                                      wire_hex },
                          head_hash },
  "signature_purposes": { login, request_authorization, roster_entry, signalling;
                          each with its inputs, signed_bytes_hex and sig_hex },
  "pairing":            { pairing_id, code, pake_password + preimage,
                          spake2_shared_secret,
                          confirm {info, okm, conf_initiator, conf_joiner},
                          sas {info, salt:null, okm_6, indices[7]} },
  "escrow":             { suite, rk_enc_scalar/pub, epoch, counter,
                          hpke_info, aad, plaintext (+ak_seed, +head_entry),
                          enc, commit_context, commit, ciphertext,
                          object_hex, negative_object_hex, negative_expect },
  "collection_object":  { collection, epoch, schema, writer_version, counter,
                          k_profile, nonce, aad, plaintext, ciphertext, object }
}
```

All hex is lowercase, unpadded, no `0x`. Every field name ending `_hex` is hex;
everything else is a literal.

### 13.2 What each vector pins

| Vector | A test consuming it asserts |
|---|---|
| `canonical_encoding` | encoding a field list produces `encoded_hex` byte for byte, and each field's own hex |
| `root` | BIP39 seed, both HKDF outputs, both public halves, the account id |
| `epoch_keys` | three distinct HKDF outputs per epoch under the exact `info` bytes, and that epoch 1 and 2 outputs differ |
| `roster_chain` | body re-encodes from the fields; `sig` verifies under the right key per `signer`/`epoch`; `H` matches; `prev_hash` links; head hash; `label_ct` decrypts to `quiet-otter-41` |
| `signature_purposes` | each signature verifies, **and** the login signature does not verify over the authz bytes |
| `pairing` | the password preimage and hash; both confirmation halves; the SAS OKM; the seven indices, cross-checked against the integer formulation |
| `escrow` | the commitment reproduces from the exporter; the blob opens to the plaintext; the plaintext carries `AK_1`; the negative object differs only in `commit` and must be refused at step 3 |
| `collection_object` | AAD construction and the XChaCha20-Poly1305 round trip |

### 13.3 Anchor values

Reproduced here so a mismatch is visible without opening the JSON.

```
mnemonic          abandon amount liar amount expire adjust cage candy arch gather drum buyer
bip39 seed        3779b041fab425e9c0fd55846b2a03e9a388fb12784067bd8ebdb464c2574a05
                  bcc7a8eb54d7b2a2c8420ff60f630722ea5132d28605dbc996c8ca7d7a8311c0
RK_sign.seed      fc638ed4282e6b1746780e533d3acc8024fbf9c824fe4ace8c44a72a886d3bba
RK_sign.pub       62ace510e2628a3664ee0d902daa81869406e0d4c5cbf8f375180a04125f4e8a
RK_enc.pub        15c0a18bc3f06bfe96cc8974aa5fae100029715242b34339a8332c68e5a3287b
account_id        b4e6cf2a2b3e9370f642957d57952c89
AK_1.sign.pub     378ee234c413ff24deb77da43b89acd384228454f16fe48fb439205bf08afbb5
AK_1.enc.pub      efdf63f2735199d5d66cd46f63eacf2b8e8e4a9ab3163981c678106d078b753b
genesis entry H   b4a598de8b12bb568b6c958ddb1f94e08828c0e0b850b1261aa796cc128d32ca
roster head H     effe053d5a91fbb922ba451d16bcc9c302c4356ff7d1f8364d2e6bdfaf7509dc
SAS okm (6)       9428374665e4  ->  indices [37, 2, 32, 55, 17, 38, 23]
escrow commit     abf06e7b706f39c69f50b9e8546cf47fc4dbde4999e08f5bc50feade3f6b13df
```

### 13.4 What is not vectorised, and why

- **SPAKE2 message bytes.** The exchange is randomised and `gospake2` exposes no
  deterministic-nonce entry point. The vectors therefore start from a fixed
  32-byte "shared secret" and pin everything downstream of it — the confirmation
  keys and the SAS, which is where every encoding bug lives. SPAKE2 itself is
  covered by an interop test between the Go and TypeScript implementations, not
  by a vector.
- **A true key-commitment collision.** A single ciphertext that opens under two
  different keys cannot be constructed for HPKE without breaking it. The negative
  vector instead flips one commitment byte, which proves the implementation
  *checks* the commitment and checks it first. The commitment property itself is
  argued in §6.5, not demonstrated.
- **The fingerprint phrase (§5.6) and the pairing wordlist (§8.1).** Both need
  vendored wordlists that do not exist in the tree yet. The derivations are fully
  specified; the vectors land in the same commit as the wordlists, generated the
  same way as everything else here.

### 13.5 Regenerating

The generator lands as a `go run` target under `internal/protocol/` with the
first M1 commit — it has no inputs other than the constants in this document.
(The build that produced the committed file is the M1 spec's scratch generator;
porting it in is the first task of M1, not a rewrite.) Regenerating MUST be a
no-op: if the file changes, either this specification changed or something
drifted, and CI fails on the diff. `govulncheck` keeps the CIRCL pin at or above v1.6.3 —
GO-2026-4550 / CVE-2026-1229 is open below it.

---

## 14. Decisions this specification made that `DESIGN.md` left open

Each of these was ambiguous or absent in the design. The choice and its reason,
in one or two sentences, so a reviewer can disagree with the decision rather than
rediscover the question.

1. **BIP39 seed, not raw entropy, as HKDF IKM.** The seed is the standard-defined
   function of the words and every BIP39 library exposes it; using the entropy
   instead would be a second, addy-specific mapping to get wrong. Empty
   passphrase — the design already rejects a 25th word.

2. **One domain prefix per structure, not one for the whole protocol.**
   `DESIGN.md` names `addy-roster-v1\0` for canonical serialisation generally.
   Taken literally that would give all four signature purposes the same prefix,
   which defeats the purpose separation the same section asks for. Resolved:
   `addy-roster-v1\0` stays exactly as written for roster entries, and every
   other structure gets its own prefix on the same pattern.

3. **One HKDF salt, `SALT_GENESIS`, everywhere except the SAS.** The design says
   "a genesis salt" without saying where it applies. A salt is a domain
   separator, not a secret, so one value is enough and a per-account one is one
   more thing to disagree about. The SAS keeps **no salt** because it follows
   Matrix exactly and a salt there would produce different emoji on each side.

4. **Root labels carry no account id.** `account_id` is derived from
   `RK_sign.pub`, so including it in `RK_sign`'s own derivation is circular.
   Everything below the root carries account id and epoch, as the design asks.

5. **`account_id = SHA-256("addy-account-id-v1\0" || RK_sign.pub)[0:16]`.** The
   design never defines it. Deriving it from the root key makes it stable across
   epochs, which §9's "an epoch transition changes the epoch and nothing else"
   requires. 128 bits is ample for a name.

6. **Epochs start at 1.** So a zeroed field is never a valid epoch.

7. **A dedicated 32-byte `nonce` in the roster entry body.** The design requires
   a client-contributed nonce in every signature; the roster entry had none.
   `prev_hash` is not a substitute, because the server chooses which chain it
   serves and so has partial control over it.

8. **`signer` is an explicit field, not an inference.** The verifier must know
   which key to check before it checks, and deriving that from `op` plus context
   is the kind of implicit rule two implementations get differently.

9. **Hygiene rotations may be signed by `AK_n.sign`; revocation rotations must be
   signed by `RK_sign`.** The design says epoch entries are `RK_sign`-signed and
   also says "any surviving device can re-key", which cannot both be true — a
   surviving device holds `AK_n`, not `RK`. Split by intent: hygiene is
   reachable from a paired device, revocation is not, because a compromised
   `AK_n` must not authorise its own successor. What this does **not** cover is
   the design's "lost the card but still hold a working laptop" case, which
   issues a *fresh phrase* and therefore a fresh `RK` and a fresh `account_id` —
   that is an account migration, not a rotation, and it is explicitly out of M1.
   Flagged for the design to resolve.

10. **A hard revoke is two entries, revoke then transition.** The design does not
    order them. Revoke first, so the reason is recorded in the epoch the device
    was in and the transition entry stays a pure epoch change.

11. **The escrow commitment is the HPKE exporter, checked before `Open`.** The
    design offers "hash the key into the AAD, or encrypt-then-MAC". The first is
    not reachable — HPKE's AEAD key is internal to the context. The second means
    a second key schedule. The exporter is in RFC 9180, present in both CIRCL and
    Go 1.26's `crypto/hpke`, and costs one HKDF-Expand.

12. **The escrow carries the whole head entry, not just its hash.** The design
    says "the signed roster head". A hash is not self-verifying; the full
    `body || sig` lets a recovering device check the head's signature itself.

13. **XChaCha20-Poly1305 for everything addy nonces itself.** Two devices writing
    the same collection under one `K_profile_n` cannot coordinate a 12-byte
    nonce counter. A 24-byte random nonce needs no coordination.

14. **The pairing code's entropy is pinned as 2 digits + two words from a 256-word
    list = 22.64 bits.** The design says "about 22 bits" without a wordlist size.
    256 is the smallest power of two that reaches it and keeps the list short
    enough to vendor and curate for phonetic distinctness.

15. **The PAKE password binds `pairing_id` but not `account_id`.** The joining
    device does not know the account id yet, so binding to it would be a binding
    one side cannot compute.

16. **Key confirmation and SAS bind both `DK_sign` public halves.** The PAKE
    proves a shared password; without the identity keys in the `info` string it
    proves nothing about who holds it.

17. **Three signalling frames, two carrying PAKE material.** The design says "a
    two-message exchange"; that is true of SPAKE2 itself. The joiner's
    confirmation rides on frame 2 and the initiator's needs a third frame, since
    the initiator cannot confirm before it has seen the joiner's message.

18. **`ts` is display-only everywhere.** The design never says what a timestamp
    is for. Nothing load-bearing may depend on a clock an attacker owns.

19. **`label_ct` must be empty for `revoke` and `epoch`.** Otherwise it is a
    covert channel in a structure the server stores verbatim.

20. **Strict decoding is normative, with a list.** The design warns about
    "sign over one encoding, verify over another" but does not say what a
    decoder must refuse. §2.3 says, item by item; trailing bytes alone would be
    enough to break the chain.
