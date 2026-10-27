# What an addy admin can and cannot do

Published **before** the admin UI existed, deliberately. Writing this boundary
down costs nothing and is most of what earns an operator's trust — and a
boundary discovered from the UI is one nobody agreed to.

The UI exists now, at `/admin`, and it was built to this document rather than
the other way round. **`OPERATOR-SIGNIN.md` is how to turn it on.**

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
| See metadata | Per sync group: its id, its owner's email if it has one, how many roster entries it has, bytes used, and when anything in it last changed |
| Change configuration | Domains, TLS, the services the box deploys |
| Run `addy panic` | Rotate every credential the box holds |

A roster entry count is not a device count. Entries include revocations and
key transitions, and the server cannot work out which devices are live without
verifying the chain, which needs keys it does not have. Nor is there a
per-device last-seen time: what the relay records is when a sync group's
objects last changed.

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

## Your first device

A sync group is created by its first device, and that is the one step in the
product that needs an invite. Mint one on the box:

```sh
docker exec addy /addy invite                      # compose
kubectl exec -it <release>-addy-0 -- /addy invite  # Helm
```

Then in OpsMaxx open **Sync & devices**, choose **This is my first device**,
and give it `https://YOUR-RELAY-DOMAIN` and the invite. The invite works once
and expires in 24 hours (`-ttl` changes that; `addy invite -list` shows what is
outstanding). Every device after the first is added by pairing with one that
is already in, and needs nothing from you. With the console turned on
(`OPERATOR-SIGNIN.md`) you can mint invites there instead.

## Upgrades, backups and rollback

Everything addy keeps is in its data directory, `/var/lib/addy` in the
container: the SQLite database, the certificates and their key, and the ACME
account. Losing it means every device re-onboards and every certificate is
reissued.

**Upgrading.** Re-run the installer. On a box that already has
`/opt/addy/.env` it keeps that file, pulls the release, replaces the compose
file and restarts; `ADDY_VERSION=0.2.0` picks a version instead of `latest`.
By hand it is `docker compose pull && docker compose up -d` in `/opt/addy`,
which keeps the old compose file. On Kubernetes, `helm upgrade` with the new
`image.tag`. Versions are written without a `v`: the image is `0.2.0`, the git
tag `v0.2.0`.

**What addy keeps for you.** Before it changes the database's schema, addy
copies the database to `addy.db.schema-<N>.<time>.bak` beside it, where `<N>`
is the schema the copy has -- the one the previous release opens. Nothing
deletes these; clear old ones out once a release has run for a while.

**Backing up.** Stop it, copy the directory out, start it. `docker cp` works on
a stopped container, and the image has no shell, so this is the way in:

```sh
cd /opt/addy
docker compose stop addy
docker cp addy:/var/lib/addy ./addy-backup-$(date +%F)
docker compose start addy
```

A copy taken while it runs can catch the database mid-write. Keep the backup
as private as the box: it holds the roster chains and the TLS key.

**Rolling back.** An older addy refuses a database a newer one has upgraded --
it says which schema it found -- so going back a version means going back to
that version's copy of the database too. Do it only when the new version
cannot run, and soon: anything written since the upgrade is lost, and a device
that synced in between will see older data than it last saw, which is what its
counters exist to notice.

```sh
cd /opt/addy
docker compose stop addy
# Which copies exist. The image has no shell, so borrow one.
docker run --rm -v addy_addy-state:/data busybox ls -l /data
# Put the copy back as the database, keeping what it replaces.
docker run --rm -v addy_addy-state:/data busybox sh -c '
  cd /data && mkdir -p replaced &&
  mv addy.db addy.db-wal addy.db-shm replaced/ 2>/dev/null;
  cp addy.db.schema-N.TIME.bak addy.db && chmod 600 addy.db'
# And the version that opens it.
sed -i 's/^ADDY_VERSION=.*/ADDY_VERSION=0.1.0/' .env
docker compose up -d addy
```

`addy_addy-state` is the volume compose made: the project takes its name from
the directory, `/opt/addy`. On Kubernetes the same files are on the claim:
scale the StatefulSet to zero, mount the claim in a throwaway pod to do the
same moves, then `helm upgrade` with the previous `image.tag`.

When the upgrade did not change the schema there is no copy, and none is
needed: the previous version opens the database as it is.

## No telemetry

No usage reporting, no analytics, no monitoring beyond the quota number an admin
needs in order to do their job. An addy instance reports nothing to anybody,
including to us.
