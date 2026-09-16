# addy

A self-hosted, end-to-end-encrypted satellite relay for
[OpsMaxx](https://github.com/OpsMaxx/OpsMaxx): device pairing, multi-device
sync, continuity between your own machines, and a deployment helper for a small
set of self-hosted services.

**Status: nothing is implemented yet.** This repository currently holds the
design of record and its scaffolding. `docs/DESIGN.md` is the complete design —
about two thousand lines of it, including the corrections an adversarial review
forced before a line of code existed. Read
[`THREAT_MODEL.md`](THREAT_MODEL.md) before you read anything else, because the
whole point of addy is what it is *not* trusted with.

## What addy is for

Everything OpsMaxx knows about you — servers, workspaces, vault entries, VPN
profiles, tunnels, preferences — lives on exactly one computer. A new laptop
means rebuilding a pile of undocumented configuration by hand; a second laptop
means the SSH key, the kubeconfig and the `.env` are each on precisely one of
them. The workarounds people reach for — a message to yourself, a screenshot of
a QR code, a token pasted into a notes app — are all worse for security than the
problem they solve.

addy fixes that **without ever being trusted with the secrets**. It is a relay,
a signalling server, a quota-metered blob store and a service-deployment helper.
OpsMaxx is its client. The server holds ciphertext and metadata, and cannot mint
a device of its own.

## What someone who owns your addy box learns

Stated in full, because a security product that is vague here is not making a
claim at all. They learn:

- how many devices you have, each one's IP address and when it is online;
- the size and change history of every encrypted collection;
- which of your devices talk to each other and when;
- your plaintext preferences (theme, font size, and the like).

They do **not** learn the contents of your servers, vault entries, VPN profiles,
tunnels, `.env` files or transferred files, and they cannot forge a roster entry,
so they cannot add a device of their own.

They can still do four things, and you should treat all four as real. See
[`THREAT_MODEL.md`](THREAT_MODEL.md), which states them plainly, and states the
relay-only and relay-plus-services deployments **separately** — turning on
service deployment genuinely changes what a compromise costs you.

> **Your recovery phrase is the whole account.** Anyone holding it can read
> everything and add a device, with or without addy. It is the one thing in this
> system with no second factor. Never type it anywhere but the OpsMaxx desktop
> app — not in a browser, not on any page, for any reason.

## Design

- [`docs/DESIGN.md`](docs/DESIGN.md) — the design of record, verbatim.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what a full server compromise does and
  does not yield.

## Licence

MIT. See [`LICENSE`](LICENSE).
