# addy threat model

**Status: checked against the code on 2026-10-29 — addy 0.1.6 and its client,
OpsMaxx 0.59.2.** Where the design commits to something that is not built yet,
this file says so next to the claim; everything else describes what ships. A
claim here that the code does not honour is a bug in this file.

This document exists because the product's entire pitch is a negative claim —
"the server does not learn your secrets" — and a negative claim that is not
stated precisely is not a claim. An earlier draft of the design said the server
"does not learn one credential", full stop. An adversarial review broke that
sentence in four independent ways before any code existed. What follows is what
survived.

---

## Two deployments, two different products

**This is the most important distinction in the document.** addy has a mode that
only relays, and a mode that also deploys containers on the same box. They have
different blast radii and the same sentence is not true of both.

| | **Relay-only** | **Relay plus service deployment** |
|---|---|---|
| Touches Docker | No | **The services run in Docker, and Docker access is host root** |
| What a full compromise yields | Ciphertext, metadata, plaintext preferences | All of that, **plus host root**, plus every credential of every service addy deployed |
| Recommended | The default | Run it on a **different box** from the relay |

The relay process itself never talks to Docker. Services are **off until you
install one**: `addy service list` prints what each one costs before you choose,
and `addy service install` only writes compose files and starts nothing — you
read them, then run them. Those files reach Docker through a proxy restricted to
the endpoints a deployment uses, which is a speed bump, not a security boundary
against an attacker who already has code execution, and the file it writes says
so rather than claiming otherwise.

Everything below describes the **relay-only** case unless it says otherwise.

---

## What a full server compromise yields

Assume the attacker owns the box completely: root, the metadata database, the
object store, and the binary addy serves.

### They learn

- **How many devices you have**, each one's IP address, and when it is online.
- **The name, size and change history of every encrypted collection** —
  `servers`, `vault`, `tunnels` and so on — not its contents, but "the vault
  changed four times on Tuesday" is real information.
- **Which of your devices talk to each other, and when.**
- **No preferences today.** The design allows a short list of plaintext
  preferences — theme, terminal font — so a brand-new device could look right
  before pairing (`internal/profile`). No relay endpoint stores them and OpsMaxx
  sends none; if that changes, this line changes with it.
- **Device public keys.** Unavoidable: authenticating a login requires them.

This is the honest cost of using a relay at all. It is minimised, never exported
and never aggregated, and it is stated here rather than pretended away.

### They do not learn

The contents of your servers, vault entries, VPN profiles, tunnels, databases,
CI/CD connections, `.env` files, transferred files, clipboard payloads, or your
device labels. All of it is encrypted on the client under a key the server has
never held and cannot derive.

**Not even the device's name.** A device's identity is a freshly generated
public key and a generated pseudonym (`quiet-otter-41`); nothing is read from the
host to produce it — no hostname, no OS username, no MAC address, no disk or
board serial, no `machine-id`. The friendly label is ciphertext, so what the
server holds for a device is a random public key and nothing else.

### They cannot

**Add a device.** The device list is an append-only hash-chained log, every
entry signed by an account key the server does not hold. A device is added by an
existing device, never by the server.

> **One exception, stated because it would otherwise be a false claim.** A device
> restored from the recovery phrase alone holds the account signing key and
> therefore authors its own roster entry, with no second human — that is the
> entire point of recovery. So the guarantee is precisely: *the server cannot add
> a device; only the account key can, whether held by a paired device or
> reconstructed from the phrase.* A phrase-authored entry is flagged as such in
> the chain and raises a loud, separate notification on every other device.

---

## The four things they can still do

Treat all four as real.

### 1. Serve you old data, or destroy it

Your devices hold the plaintext, so this is a **recovery** problem rather than a
disclosure one. But a device restoring from scratch cannot tell an old copy from
a current one except by comparing the roster hash against a device you still
have.

What the client does about it:

- Every sealed object carries a counter *inside* the ciphertext. It is bound by
  the AEAD under the account key, not signed — any device on the account can
  write one, the relay cannot. Each device keeps the highest counter it has seen
  for every object, through resyncs and re-keys, and refuses anything lower.
- Recovery shows the **Account fingerprint** — words derived from the roster
  head — *before* it adds anything, and asks you to compare them with another of
  your devices. It ends on a device list review.
- **Not built yet:** the printed recovery card that would carry the roster head
  and device count as an anchor for when no other device survives. Until it
  ships, a recovery with no second device to compare against trusts the relay's
  roster.

### 2. Serve you a modified web portal

The portal is attacker-controlled software. It can render a convincing "verify
your recovery phrase" prompt, and it can display a fabricated roster hash —
defeating the integrity check by *being* the thing that reports it.

Two rules follow, both absolute:

- **The recovery phrase is entered in the OpsMaxx desktop app and nowhere else.**
  No browser, ever, on any page, for any reason. The portal has no field for it,
  and a page asking for it is by definition an attack.
- **The roster head is compared between two OpsMaxx devices**, as the Account
  fingerprint words on Sync & devices — never read from the portal, which is
  software the attacker controls. An integrity check reported by the thing being
  checked is not a check.

The portal also ships **no service worker**, because one would survive both
`addy panic` and `addy reset --hard` and quietly outlive the remediation meant to
remove it.

### 3. Read every credential of any service addy deployed for you

The Vaultwarden admin token, the headscale keys, the WireGuard server key, the
frp token. That is what deploying a service *means*. See the two-deployments
table above.

### 4. Crack any backup bundle you stored on them

At the strength of the passphrase you chose. The design gates the addy backup
destination behind four preconditions precisely because of this — including
sealing the bundle a second time under the account key before it leaves your
machine, and excluding the account key itself from the bundle.

---

## What rotation does and does not undo

Two kinds of revocation, because they are two different events:

| | **Soft revoke** | **Hard revoke / re-key** |
|---|---|---|
| Authorised by | Any paired device | The recovery phrase |
| Does | Removes the device from the roster; honest devices stop encrypting to it | Mints a new account epoch, re-seals everything, re-seals to each surviving device |
| Good for | "I sold my old laptop" | "My laptop was stolen"; compromise mode |
| Does **not** | Stop a malicious holder of the old epoch key re-admitting itself | — |

**Rotation protects the future, never the past.** Anything the attacker already
fetched and decrypted before revocation stays compromised. A revoked device also
keeps the old epoch key and everything it already downloaded.

**A revoked device that never comes online again is never wiped.** Revocation
reaches a machine when that machine next connects. For a machine that does not,
full-disk encryption is the control that matters. The Remove button says that a
machine kept offline never hears, and that a stolen one also needs the account
key changed, rather than letting "remove" be read as "wipe".

---

## The recovery phrase

**It is a bearer token for the whole estate minus the vault** — unhardened,
un-rate-limited, and usable by anyone holding it from anywhere. Calling it a
"recovery phrase" invites the mental model of an account-recovery email, which is
the wrong one and leads people to store it accordingly.

addy has **no password reset, no email verification and no account recovery**,
because it has no account in the usual sense — it has a signing key it was handed
once. The vault is the deliberate exception: it crosses devices as opaque
ciphertext addy never opens, so the phrase reconstructs everything *except* vault
contents, which still need the master password you already know. Two secrets,
each doing the job it was designed for.

**What never left the old machine is not recovered either.** A password, key
file or connection string saved only in a machine's keychain stays on that
machine, so neither a second device nor a recovery brings it back. OpsMaxx
offers to move such credentials into the vault, from the vault itself.

A credential that is a vault entry does come back, once the vault is unlocked:
since OpsMaxx 0.59.2 a server or database record carries which entry it uses (a
pointer, never the value), as CI connections, VPN profiles and env secrets
already did. Because a record that names both an address and a credential is
exactly what a compromised device on the account would forge, a link that
arrives new or changed is not used on a device until a person there confirms
it, and the question names the entry it would release; background checks skip
it until then. The relay cannot write such a record at all: records are sealed
under the account key, so it can only withhold one, and an older copy it
replays is refused.

---

## The admin boundary

An admin holds **availability and identity** power, never **confidentiality**.

They can delete a user, invite one, change configuration, and see metadata —
device count, bytes used, last seen. They can see no collection, no transfer and
no paste, because none of it is decryptable to them. Deleting a sync group
removes everything stored for it and ends its open sessions; it cannot decrypt
anything first, so it is a deletion and not an export, and the console says so.

There is no organisation-level account recovery and there will not be. It is a
deliberate backdoor and the exact inverse of the roster's premise.

---

## Known gaps

Open in this release, each one deliberately listed rather than left to be found.

- **First contact is trust-on-first-use.** Creating an account and the pairing
  rendezvous trust the relay's TLS key the first time; every later connection
  is pinned to it.
- **The request signature covers the method, path and body, not the query
  string.** TLS and the login's channel binding stop a third party; the relay
  itself is the party that could exploit it, and it already chooses what to
  answer.
- **A removed device keeps its overlay node.** Removing a device ends its relay
  sessions, but its headscale node, if it joined the overlay, stays until it is
  deleted there.
- **A cloned machine is the same device.** A disk image, a VM clone or a
  migration tool that copies the keychain produces a second machine the roster
  cannot tell from the first.
- **Restoring a relay from backup rewinds it.** To your devices that looks
  exactly like a rollback attack, and they refuse it rather than accept it.
  Nothing yet repairs a restored relay from the devices that are ahead of it.

---

## Non-goals

addy does not defend against a compromised **client**. A device with malware on
it holds the plaintext, the device key and, if it is paired, the account key.
Nothing in this design changes that, and no relay design could.
