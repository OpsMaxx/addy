# What an addy admin can and cannot do

Published **before** the admin UI exists, deliberately. Writing this boundary
down costs nothing and is most of what earns an operator's trust — and a
boundary discovered from the UI is one nobody agreed to.

## The rule

**An admin holds AVAILABILITY and IDENTITY power, never CONFIDENTIALITY.**

They run the box. They decide who may have an account and how much space it
gets, and they can destroy any of it. What they cannot do is read any of it,
and that is not a policy they are trusted to follow — it is that the data is
ciphertext and they hold no key.

## What an admin can do

| | |
|---|---|
| Invite a user | Create an invite token, which is itself the permission to register |
| Remove a user | Delete their account, roster and objects |
| Set a quota | Change how many bytes an account may occupy |
| See metadata | Account id, device count, bytes used, when each device was last seen |
| Change configuration | Domains, TLS, the services the box deploys |
| Run `addy panic` | Rotate every credential the box holds |

## What an admin cannot do

- **Read any collection.** Servers, vault entries, VPN profiles, tunnels,
  databases, CI/CD connections, `.env` contents, transferred files — all sealed
  under a key that has never been on the box.
- **Read a device's label.** The pseudonym is ciphertext too, so what the server
  holds for a device is a random public key and nothing else.
- **Add a device.** The roster is signed by an account key the server does not
  have. A device is added by an existing device, never by the server.
- **Read a one-time paste.** Its key lives in the URL fragment, which browsers
  never transmit.
- **Recover an account.** There is no organisation-level recovery and there will
  not be one. It is a deliberate backdoor and the exact inverse of the roster's
  premise.

## "Remove user" is a deletion, not an export

It deletes the account's prefix and revokes its tokens. It cannot decrypt
anything first, so there is no version of it that produces readable data — the
UI says so, and offers the user's own devices as the only way to get anything
out.

An admin who wants a user's data has to ask the user. That is not a limitation
of the implementation; it is the product.

## What an admin CAN still do that is worth stating plainly

The threat model does not pretend an admin is harmless:

- They can **destroy** an account. Every device holds the plaintext, so that is
  a recovery problem rather than a disclosure one — but a user whose devices are
  all offline can lose the lot.
- They can **serve old data**, which is what the monotonic counters and the
  roster pin exist to catch.
- They can **serve a modified portal**. Never type a recovery phrase into a
  browser, and compare a roster fingerprint between two OpsMaxx windows rather
  than reading it from a page the operator controls.
- If the box also **deploys services**, they hold those services' credentials,
  because deploying a service means being given them. See `THREAT_MODEL.md`;
  relay-only and relay-plus-services are different products in a security sense.

## No telemetry

No usage reporting, no analytics, no monitoring beyond the quota number an admin
needs in order to do their job. An addy instance reports nothing to anybody,
including to us.
