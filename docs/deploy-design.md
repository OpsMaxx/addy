# addy — deployment layer

> Research note, 2026-09-17. Everything about Garage below was verified against
> upstream at tag `v2.4.1` (the pin in `DESIGN.md`) — the published OpenAPI
> document, the book sources in `doc/book/`, and where behaviour mattered, the
> Rust source itself. URLs are listed at the bottom. Where upstream disagrees
> with `DESIGN.md`, it is called out as a **FINDING** rather than quietly
> reconciled.

---

## 0. Findings first: where upstream disagrees with the design

`DESIGN.md` (written 2026-09-15) says:

> **Garage does not serve a byte until `layout assign` and `layout apply` have
> run**, and access keys come from its admin API. That bootstrap belongs in M0's
> installer, not discovered on first boot.

The *consequence* is right. The *mechanism* has been obsolete since Garage
v2.3.0 (released 2026-04-16), four months before the design was written.

### FINDING 1 — `garage server --single-node --default-bucket` replaces the entire bootstrap

Garage v2.3.0 landed PR #1329, "Make initial setup easier". `garage server`
grew three flags:

| Flag | Effect |
|---|---|
| `--single-node` | Auto-creates and applies a one-node layout at startup if none exists |
| `--default-access-key` | Creates an access key from `GARAGE_DEFAULT_ACCESS_KEY` / `GARAGE_DEFAULT_SECRET_KEY` |
| `--default-bucket` | Creates a bucket named `GARAGE_DEFAULT_BUCKET` and grants the default key read+write+owner on it. Implies `--default-access-key`. |

This is not a convenience wrapper around the admin API — it runs *inside*
`run_server()` before the API servers bind, in `initial_config()`
(`src/garage/server.rs`). Read from the v2.4.1 source, it behaves as follows:

- **`--single-node` requires `replication_factor = 1`** in the config file, and
  returns a hard startup error otherwise.
- It reads the current layout version. `0` → build and apply version 1, with
  zone hardcoded to `"dc1"`, tag `"default"`, and **capacity auto-detected** from
  the data disk's total size (falling back to 1 GiB if that cannot be read).
  Version `1` → **do nothing**. Version `> 1` → **refuse to start**, with
  "Remove the --single-node flag to run the server in full mode."
- It refuses if any other node is already known to the cluster.
- `--default-access-key` looks the key id up in the key table. Absent → create
  it (with `allow_create_bucket = true`). Present with the *same* secret → do
  nothing. Present with a **different** secret → hard startup error. Previously
  deleted → hard startup error.
- `--default-bucket` creates the bucket if its global alias does not resolve,
  and then re-applies `read+write+owner` for the default key **on every boot**.

So the whole bootstrap is idempotent *by construction, upstream*, and it is not
a sequence the installer has to orchestrate at all. It is a flag on the
long-running process and a handful of environment variables.

**Recommendation: addy uses this path.** It deletes the node-id lookup, the
layout staging, the version arithmetic, the `apply --version N` hazard, the
key-create-twice hazard, and the "what if the installer dies between assign and
apply" question — all of which are covered in §1.2 anyway, because they are
still the right answer for anyone on a pre-v2.3.0 binary or growing past one
node.

### FINDING 2 — the access key is now chosen by the installer, not minted by Garage

`--default-access-key` takes the key id *and* secret from the environment.
Garage v2.3.0 also relaxed `Key::import` (PR #1262). The v2.4.1 rule, read from
`src/model/key_table.rs`:

```
key_id:     >= 8 chars, [A-Za-z0-9-_.] only
secret_key: >= 16 chars, graphic ASCII (U+0021–U+007E) only
```

The old `GK` + exactly 24 hex digits rule is gone. Upstream's own quick start
now suggests `GK$(openssl rand -hex 16)`, which is 34 characters — it would have
been rejected by the pre-v2.3.0 validator.

This inverts the design's data flow in a way that is strictly better for an
installer: the credential is generated locally, written to a `0600` env file
*before* anything starts, and never has to be scraped back out of an API
response. Re-running the installer with the same env file is a no-op; re-running
it with a *regenerated* secret is a hard, loud startup failure rather than
silent divergence — which is the correct failure.

Note `ImportKey` exists on the admin API and is explicitly **not** for this:
"This feature must only be used for migrations and backup restore. **Do not use
it to generate custom key identifiers or you will break your Garage cluster.**"
The `--default-access-key` path is the supported one.

### FINDING 3 — `garage json-api` removes the need for an admin token in the installer

Since v2.0.0 there is `garage json-api <Endpoint> '<json>'`, which proxies admin
API calls through Garage's **internal RPC**, discovering connection parameters
the same way every other `garage` CLI command does. Upstream: "it does not
require any form of authentication". For anything the installer still needs to
do out-of-band, this is strictly simpler than minting a bearer token and
curl-ing `localhost:3903`.

### FINDING 4 — the master `admin_token` is now discouraged

The design's implied model is one `admin_token` in the config. Upstream v2.4.1
says, of the config-file master tokens: *"With the introduction of multiple
user-defined admin tokens, the use of master API tokens is now discouraged."*
Scoped, expiring tokens are created with `garage admin-token create --scope
... --expires-in 30d`, are shown exactly once, and are stored hashed.

addy still wants a long-lived admin credential (it manages per-user quota and
will want `UpdateBucket` for bucket quotas). The right shape is a **scoped**
token limited to the endpoints `internal/objects` actually calls, created at
install time and stored in the env file — not `admin_token` in `garage.toml`.
See §2.

### FINDINGS 5–7 — the three consequences the design already records are all confirmed

Verified against `doc/book/reference-manual/s3-compatibility.md` at v2.4.1:

- **No bucket policies.** `PutBucketPolicy`, `GetBucketPolicy`,
  `DeleteBucketPolicy`, `GetBucketPolicyStatus` are all "❌ Missing", and "All
  endpoints that are missing on Garage will return a 501 Not Implemented."
  `internal/objects` really is the only isolation boundary. Unchanged.
- **No object versioning.** "Garage does not (yet) support object versioning."
  `GetBucketVersioning` is documented as a stub that always answers "not
  enabled"; `PutBucketVersioning` is missing. Unchanged.
- **Path-style is required** unless `[s3_api] root_domain` is set and wildcard
  DNS exists for it. We are not doing wildcard DNS for the object store, so
  `minio.BucketLookupPath` stands. Unchanged.

### FINDING 8 — `dxflrs/garage` is `FROM scratch`

The official image's Dockerfile at v2.4.1 is six lines: `FROM scratch`, two
`ENV`, `COPY result/bin/garage /`, `CMD ["/garage", "server"]`.

There is no shell, no `curl`, no `wget`, no `sh`. Every compose healthcheck
example on the internet that uses `CMD-SHELL` or `curl -f http://localhost:3903/health`
will fail in this container with an exec error, not a health failure — which
reads as "unhealthy for an unknown reason" in `docker compose ps`.

The fix landed upstream one release ago: **`garage health` (v2.4.0, PR #1373)**
sets exit code 1 when the cluster is unavailable. So the healthcheck is
`["CMD", "/garage", "health", "-q"]` and nothing else. Confirmed in
`src/garage/cli/remote/cluster.rs`: status `"unavailable"` returns `Err`,
everything else returns `Ok`.

---

## 1. Garage bootstrap, exactly

### 1.1 The path addy takes

Prerequisite in `garage.toml`: `replication_factor = 1`. Without it,
`--single-node` is a startup error, and the error text names the setting.

```bash
# Written once by install.sh into deploy/compose/.env, mode 0600.
GARAGE_DEFAULT_ACCESS_KEY=addy-$(openssl rand -hex 8)      # >= 8 chars, [A-Za-z0-9-_.]
GARAGE_DEFAULT_SECRET_KEY=$(openssl rand -hex 32)          # >= 16 chars, graphic ASCII
GARAGE_DEFAULT_BUCKET=addy
```

```yaml
# ...and the container command becomes:
command: ["/garage", "server", "--single-node", "--default-bucket"]
```

That is the whole bootstrap. First boot: layout v1 applied, key created, bucket
created, permissions granted. Every subsequent boot: four lookups, zero writes,
except the bucket-key permission grant which is re-applied unconditionally and
is itself idempotent.

**Idempotency, stated per case, because the installer will be re-run:**

| Re-run scenario | Behaviour |
|---|---|
| Same env file, container restarted | No-op. Safe. |
| Same env file, `install.sh` re-run | No-op. Safe. |
| Secret regenerated in `.env` | **Refuses to start**, names the key id. Loud, correct, recoverable by restoring the secret. |
| Key deleted via admin API, then re-run | **Refuses to start** — Garage tombstones deleted keys and will not resurrect one. Recover by choosing a new key id. |
| Layout already at version > 1 (someone ran `layout apply` by hand) | **Refuses to start.** This is the one failure mode `--single-node` introduces, and §1.2 is the escape hatch. |
| Data volume wiped, env file kept | Full re-bootstrap at layout v1. Safe. |
| Env file wiped, data volume kept | New key id created; the old key still exists and still has the grants. Harmless but leaves a stale key. `install.sh` therefore treats `.env` as the source of truth and never regenerates it if it exists (§3). |

### 1.2 The explicit path — still needed, and the only path before v2.3.0

Keep this in `docs/` and in one guarded branch of the installer, for: an
operator pinned to an older Garage, a box where layout version is already `> 1`,
and the eventual second node. Endpoints verified from the v2 OpenAPI document
(spec `info.version` is `v2.3.0`; all paths are `POST`/`GET /v2/<OperationId>`,
bearer auth, default admin bind `:3903`).

**Step 1 — obtain the node id.** Two equivalent forms.

```bash
garage node id -q                  # prints <64-hex-node-id>[@<rpc_public_addr>]
garage json-api GetClusterStatus   # -> { "layoutVersion": N, "nodes": [ { "id": ..., "isUp": true, ... } ] }
```

`node id -q` appends `@host:port` when `rpc_public_addr` is set, so a script
must `cut -d@ -f1`. **Idempotent** (pure read).

**Step 2 — stage the role.** CLI flags, read from `AssignRoleOpt` in
`src/garage/cli/structs.rs`:

```bash
garage layout assign -z dc1 -c 1G -t default <node_id_or_prefix>
#   -z / --zone      required for a storage node
#   -c / --capacity  bytes, suffixes B KB MB GB TB PB. IGNORED for a single node.
#   -t / --tag       repeatable
#   -g / --gateway   storage-less node (mutually exclusive with -c)
```

Over the API this is `POST /v2/UpdateClusterLayout`, and the shape is **not** the
same as the CLI — capacity is a raw integer of **bytes**, not a suffixed string:

```json
{ "roles": [ { "id": "<64-hex>", "zone": "dc1", "capacity": 1073741824, "tags": ["default"] } ] }
```

`capacity: null` means gateway. Removal is a different variant of the same union:
`{ "id": "<64-hex>", "remove": true }`.

**Idempotency: qualified.** The call writes into a *staging area*, not the
layout. Re-running with identical values re-stages the same value
(`update_in_place`), so the staged set is unchanged — safe. Re-running with
*different* values silently replaces the staged role, which is the dangerous
case. **Guard: read `GET /v2/GetClusterLayout` first; if `version >= 1` and
`roles[]` already contains this node id with the intended zone and capacity,
skip steps 2 and 3 entirely.**

**Step 3 — apply.** This is the one step that is genuinely not safe to re-run.

```bash
garage layout apply --version <N>          # POST /v2/ApplyClusterLayout {"version": N}
```

`N` must be **exactly `1 + current version`**, and the command fails otherwise —
which is the safety measure, and is why the parameter exists at all. Upstream's
warning is unusually blunt: *"Never make several calls to `garage layout apply`
with the same value. Doing so can lead to several different layouts with the
same version number, in which case your Garage cluster will become
inconsistent."*

**How to make it safe to re-run:** never hardcode `N`, and never `N=1`. Derive
it, and only call at all when there is something to apply:

```bash
layout="$(garage json-api GetClusterLayout)"
staged="$(printf '%s' "$layout" | jq '.stagedRoleChanges | length')"
if [ "$staged" -gt 0 ]; then
  garage json-api ApplyClusterLayout "{\"version\": $(printf '%s' "$layout" | jq '.version + 1')}"
fi
```

The `stagedRoleChanges` length is the idempotency key. Empty staging means the
previous run got all the way through, and there is nothing to apply — which is
exactly the state a crashed-then-retried installer needs to distinguish from
"assigned but not applied". `POST /v2/RevertClusterLayout` clears staging if a
half-finished run left something wrong in it.

**Step 4 — create the access key.**

```bash
garage key create addy                       # POST /v2/CreateKey {"name":"addy","neverExpires":true}
```

**NOT idempotent, and the trap is quiet.** Garage key *names* are not unique —
the identity is `accessKeyId`. A second `CreateKey` with the same name produces a
second key with a different id, and nothing complains. An installer that
re-creates on every run leaves a pile of live credentials behind.

The good news, and it differs from AWS: **Garage will show a secret key again.**
`GET /v2/GetKeyInfo?id=<id>&showSecretKey=true` returns `secretAccessKey`, so a
re-run can *recover* rather than recreate:

```bash
existing="$(garage json-api ListKeys | jq -r '.[] | select(.name=="addy") | .id' | head -n1)"
if [ -n "$existing" ]; then
  garage json-api GetKeyInfo "{\"id\":\"$existing\",\"showSecretKey\":true}"
else
  garage json-api CreateKey '{"name":"addy","neverExpires":true}'
fi
```

Both return the same `GetKeyInfoResponse` shape, so the caller parses one thing.
`CreateKey` also accepts `allow: {"createBucket": true}`, `expiration`
(RFC 3339) and `neverExpires`. Set `neverExpires` explicitly — a relay whose
object-store credential silently expires is a four-hour outage.

**Step 5 — create the bucket.**

```bash
garage bucket create addy                    # POST /v2/CreateBucket {"globalAlias":"addy"}
```

**NOT idempotent** — global aliases are unique and a second create errors.
Guard with `GET /v2/GetBucketInfo?globalAlias=addy` and skip on a hit; the
response carries the `id` that step 6 needs regardless.

**Step 6 — grant the key access to the bucket.**

```bash
garage bucket allow --read --write --owner addy --key addy
# POST /v2/AllowBucketKey {"bucketId":"<id>","accessKeyId":"<id>","permissions":{"read":true,"write":true,"owner":true}}
```

**Idempotent by construction**, and worth reading upstream's own disclaimer
before relying on that: *"Flags in permissions which have the value true will be
activated. Other flags will remain unchanged."* It is purely additive. `false`
does **not** revoke — revocation is `DenyBucketKey`. So re-running the grant is
always safe, and "set permissions to exactly this" is not an operation that
exists. `internal/objects` should never assume otherwise.

Note `bucketId` is the bucket's internal id, not its alias — step 5's response
or `GetBucketInfo` is where it comes from.

**Optional step 7 — the scoped admin token addy itself uses.**

```bash
garage admin-token create --expires-in 365d \
  --scope ListBuckets,GetBucketInfo,ListKeys,GetKeyInfo,CreateKey,AllowBucketKey,DenyBucketKey,UpdateBucket \
  addy
```

Shown exactly once, stored hashed, identified afterwards by a 32-hex prefix.
**Not idempotent** — guard with `garage admin-token list`. Prefer this over
`admin_token` in `garage.toml` (FINDING 4). Give it an expiry and let `addy
panic` be what rotates it, which is consistent with the design's rule that
`panic` must know about every credential the box holds.

### 1.3 "Does not serve a byte until the layout is applied" — confirmed, and how to wait for it

The claim holds. Before a layout exists there are no storage nodes, so no
partition has quorum, and `GET /health` on the admin port answers **503**. The
compose healthcheck in §2 is exactly this check, which means
`depends_on: { garage: { condition: service_healthy } }` is a real gate on "the
object store can take a PUT", not on "the process started". That is the whole
reason addy does not have to retry its first S3 call.

---

## 2. `deploy/compose/docker-compose.yml`

Two design constraints drive the shape: **addy is the only thing bound to 80 and
443**, and **everything else is loopback**. A third constraint comes from the
embedded TURN server, and it is the one that decides the networking mode.

**addy uses `network_mode: host`.** Three independent reasons, any one of which
is sufficient:

1. **The UDP relay range.** Publishing a port range with `-p a-b:a-b/udp` costs
   one `docker-proxy` process and one NAT rule *per port*. A few hundred ports
   is minutes of startup and hundreds of megabytes of RSS; the design's literal
   49152–65535 is 16384 ports and will wedge the daemon.
2. **TURN needs the real client source address.** With the userland proxy
   enabled (the default on many installs) published UDP arrives from the proxy,
   not the peer. A TURN server that sees every client at the same address cannot
   do permissions or channel binding correctly.
3. **IPv6.** The default bridge is IPv4-only unless `enable_ipv6` and
   `ip6tables` are configured in `daemon.json`. Host networking inherits the
   host's IPv6 without any of that — and §5 explains why an AAAA record you
   cannot serve is the single most expensive way to fail an ACME order.

Garage then publishes to `127.0.0.1` only, and addy reaches it at
`127.0.0.1:3900`. That is "loopback-only" in the strongest sense available: the
S3 and admin ports are not reachable from another host even if the firewall is
wrong, because they are not bound to a routable address.

```yaml
# deploy/compose/docker-compose.yml
#
# addy + Garage, single box. `install.sh` writes .env next to this file and
# never edits this file.
#
# WHAT BREAKS IF THIS IS WRONG
#
# - Garage's image is FROM scratch. It has no shell and no curl. A healthcheck
#   written as CMD-SHELL or curl fails with an exec error that surfaces as
#   "unhealthy", and the operator spends an hour debugging the cluster instead
#   of the healthcheck. `/garage health -q` is the only form that works.
# - Garage refuses to start if a secret FILE is group- or world-readable. The
#   secrets here are passed by environment from .env (mode 0600), not as files,
#   which sidesteps that check entirely. If you switch to *_file, you own the
#   0600 too.
# - addy is host-networked, so it is NOT on the compose bridge and CANNOT
#   resolve `garage` by service name. It must use 127.0.0.1:3900.

services:
  garage:
    image: dxflrs/garage:v2.4.1
    container_name: addy-garage
    restart: unless-stopped
    command: ["/garage", "server", "--single-node", "--default-bucket"]
    environment:
      # Consumed by --single-node/--default-bucket at startup. See FINDING 2:
      # these are chosen by the installer, not minted by Garage.
      GARAGE_DEFAULT_ACCESS_KEY: ${GARAGE_DEFAULT_ACCESS_KEY:?run install.sh}
      GARAGE_DEFAULT_SECRET_KEY: ${GARAGE_DEFAULT_SECRET_KEY:?run install.sh}
      GARAGE_DEFAULT_BUCKET: ${GARAGE_DEFAULT_BUCKET:-addy}
      GARAGE_RPC_SECRET: ${GARAGE_RPC_SECRET:?run install.sh}
    ports:
      # Loopback only, and only the two an operator needs from the host:
      # 3900 so `aws s3` works for debugging, 3903 for the admin API.
      # 3901 (RPC) and 3902 (web) are deliberately not published at all.
      - "127.0.0.1:3900:3900"
      - "127.0.0.1:3903:3903"
    volumes:
      - ./garage.toml:/etc/garage.toml:ro
      - garage-meta:/var/lib/garage/meta
      - garage-data:/var/lib/garage/data
    healthcheck:
      # `garage health` exits 1 when the cluster is unavailable (v2.4.0+).
      # Before the layout is applied there are no storage nodes, so this stays
      # red until the bootstrap in §1 has actually completed -- which is what
      # makes depends_on below mean "can take a PUT".
      test: ["CMD", "/garage", "health", "-q"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 30s

  addy:
    image: ghcr.io/opsmaxx/addy:${ADDY_VERSION:-latest}
    container_name: addy
    restart: unless-stopped
    network_mode: host          # see the three reasons above
    command: ["serve"]
    environment:
      ADDY_DOMAIN: ${ADDY_DOMAIN:?run install.sh}
      ADDY_ACME_EMAIL: ${ADDY_ACME_EMAIL:-}
      ADDY_S3_ENDPOINT: http://127.0.0.1:3900
      ADDY_S3_REGION: garage
      ADDY_S3_BUCKET: ${GARAGE_DEFAULT_BUCKET:-addy}
      ADDY_S3_ACCESS_KEY: ${GARAGE_DEFAULT_ACCESS_KEY:?}
      ADDY_S3_SECRET_KEY: ${GARAGE_DEFAULT_SECRET_KEY:?}
      ADDY_GARAGE_ADMIN: http://127.0.0.1:3903
      ADDY_GARAGE_ADMIN_TOKEN: ${GARAGE_ADMIN_TOKEN:-}
      ADDY_TURN_SECRET: ${ADDY_TURN_SECRET:?run install.sh}
      ADDY_TURN_RELAY_MIN: ${ADDY_TURN_RELAY_MIN:-49160}
      ADDY_TURN_RELAY_MAX: ${ADDY_TURN_RELAY_MAX:-49360}
    volumes:
      - addy-state:/var/lib/addy      # SQLite + certmagic storage + exported PEM
    depends_on:
      garage:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/addy", "selftest", "--quick"]
      interval: 30s
      timeout: 20s
      retries: 3
      start_period: 90s           # first boot includes an ACME order

volumes:
  garage-meta:
  garage-data:
  addy-state:
```

Companion `garage.toml`, written by the installer, mode `0644` (it contains no
secret — every secret arrives by environment):

```toml
metadata_dir = "/var/lib/garage/meta"
data_dir     = "/var/lib/garage/data"
db_engine    = "lmdb"

# Required by --single-node. Garage refuses to start otherwise, and says so.
replication_factor = 1

rpc_bind_addr = "127.0.0.1:3901"
# rpc_secret comes from GARAGE_RPC_SECRET. No rpc_public_addr: there is no
# second node to contact this one, and leaving it unset keeps `garage node id`
# from printing a misleading address.

[s3_api]
s3_region     = "garage"
api_bind_addr = "[::]:3900"
# No root_domain. Without it, vhost-style addressing does not exist, which is
# why minio.BucketLookupPath is mandatory rather than merely recommended.

[admin]
api_bind_addr = "[::]:3903"
# No admin_token and no metrics_token. Master tokens are discouraged upstream
# (FINDING 4); addy uses a scoped `garage admin-token` instead, and /metrics is
# unreachable from off-box because 3903 is published to 127.0.0.1 only.
```

### Secrets: what is generated, where it lives

| Secret | Generated by | Lives in | Rotated by |
|---|---|---|---|
| `GARAGE_RPC_SECRET` | `openssl rand -hex 32` (upstream's own instruction: 32 bytes hex) | `.env`, mode 0600 | `addy panic` |
| `GARAGE_DEFAULT_ACCESS_KEY` | `addy-$(openssl rand -hex 8)` | `.env` | `addy panic` (create new, re-grant, deny old) |
| `GARAGE_DEFAULT_SECRET_KEY` | `openssl rand -hex 32` | `.env` | as above — note it **cannot** be changed in place; changing it is a startup error (FINDING 1) |
| `GARAGE_ADMIN_TOKEN` | `garage admin-token create --scope ...` after first healthy boot | `.env` | `addy panic` |
| `ADDY_TURN_SECRET` | `openssl rand -hex 32` | `.env` | `addy panic` |

`.env` is `0600`, owned by root, and `install.sh` **never regenerates it if it
exists**. That single rule is most of what makes the installer re-runnable.

A single-node Garage does not strictly need an RPC secret, but it refuses to
start without one, and generating it is one line. Do not omit it and do not
share it with anything.

---

## 3. `install.sh`

House style, with two deviations recorded rather than hidden:

- **It carries its own retry instead of sourcing `lib/net-retry.sh`.** A
  `curl | sh` installer is one file by definition; there is no sibling to
  source. The function is the same shape and the same backoff.
- **It re-execs itself under bash.** A shebang is ignored when a script is
  piped, so `curl … | sh` runs under `/bin/sh`, which on Debian and Ubuntu is
  dash: no `pipefail`, no arrays, no `[[`. And a truncated download executes
  whatever prefix arrived. Both are solved by downloading to a file first and
  wrapping every statement in a function that is only called on the last line.

```sh
#!/usr/bin/env sh
#
# addy installer. Fetch-and-run:
#
#   curl -fsSL https://get.addy.example/install.sh | sh
#   curl -fsSL https://get.addy.example/install.sh | sh -s -- --yes --domain addy.example.com
#
# WHAT BREAKS IF THE PREFLIGHT IS SKIPPED
#
# certmagic obtains its certificate with an ACME HTTP-01 challenge, which needs
# (a) DNS for the domain already resolving to THIS box, publicly, and (b) port
# 80 reachable from the internet -- both AT INSTALL TIME, not eventually. A box
# that fails either gets a relay that starts, binds 443, and serves a TLS error
# to every client forever, with the real cause four layers down in a log. The
# embedded TURN server has the same shape of problem one layer further out: a
# default-denied UDP relay range gives a daemon that reports healthy and relays
# nothing, which is the worst possible first impression and is exactly what
# DESIGN.md says the installer exists to prevent.
#
# So this script REFUSES WITH THE REASON. It does not warn and continue.
#
# THE TOP OF THIS FILE IS DELIBERATELY sh, NOT bash. A shebang is ignored when a
# script arrives on stdin, so `curl | sh` runs this under dash on every Debian
# derivative. The only job of the sh prologue is to land the real script on disk
# and re-exec it under bash -- which also fixes the other half of the problem,
# that a TRUNCATED download would otherwise execute its first N lines.

set -eu

ADDY_INSTALLER_URL="${ADDY_INSTALLER_URL:-https://get.addy.example/install.sh}"

if [ -z "${ADDY_REEXEC:-}" ]; then
  if [ ! -t 0 ] || [ ! -f "$0" ]; then
    command -v bash >/dev/null 2>&1 || { echo "addy: bash is required" >&2; exit 1; }
    tmp="$(mktemp)" || exit 1
    # Not retried: if the installer itself cannot be fetched there is nothing
    # sensible to fall back to, and the curl error is the whole message.
    curl -fsSL "$ADDY_INSTALLER_URL" -o "$tmp" || {
      echo "addy: could not download the installer from $ADDY_INSTALLER_URL" >&2
      rm -f "$tmp"; exit 1
    }
    ADDY_REEXEC=1 exec bash "$tmp" "$@"
  fi
fi

# ---------------------------------------------------------------------------
# Everything below is bash, and everything below is inside main(), which is
# called on the very last line. A partial file therefore does nothing at all.
# ---------------------------------------------------------------------------

set -euo pipefail

ADDY_MIN_MEM_KB=1900000        # ~2 GiB, allowing for what the kernel reserves
ADDY_MIN_CPUS=2
ADDY_MIN_DISK_KB=20971520      # 20 GiB on the docker data root
ADDY_RELAY_MIN=49160
ADDY_RELAY_MAX=49360           # 200 ports. Narrow on purpose: see NOTE below.
INSTALL_DIR="${ADDY_INSTALL_DIR:-/opt/addy}"

# NOTE on the relay range. DESIGN.md names 49152-65535, which is the ephemeral
# range coturn defaults to. Two reasons to narrow it here and hold the narrowing
# in one place:
#   - WireGuard's 51820 sits inside it, and the collision is intermittent and
#     start-order-dependent, which is the worst kind to debug.
#   - It is 16384 ports. Every firewall rule, every provider firewall form and
#     every `-p` publication scales with that number. 200 concurrent relayed
#     sessions is far past what a single-box relay will see.

log()  { printf '==> %s\n' "$*"; }
warn() { printf '==> %s\n' "$*" >&2; }

# Refuse with the reason. Every preflight failure comes through here so that
# they all read the same and all name the fix.
refuse() {
  printf '\n' >&2
  printf 'addy: REFUSING TO INSTALL\n\n' >&2
  printf '  %s\n\n' "$1" >&2
  [ "$#" -gt 1 ] && printf '  Fix: %s\n\n' "$2" >&2
  exit 1
}

# Same four attempts and 5s/15s/45s backoff as the house net-retry.sh, and the
# same rule that the command's own output is never captured or silenced -- on
# the last attempt the underlying error is the only thing that explains what
# went wrong.
retry_network() {
  local what="$1"; shift
  local attempt=1 delay=5
  while :; do
    "$@" && return 0
    if [ "$attempt" -ge 4 ]; then
      warn "$what failed four times; giving up"
      return 1
    fi
    warn "$what failed (attempt $attempt of 4); retrying in ${delay}s"
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 3))
  done
}

# --- preflight: the box itself -------------------------------------------

check_root() {
  [ "$(id -u)" -eq 0 ] || refuse \
    "This installer must run as root; it writes to $INSTALL_DIR and talks to the Docker socket." \
    "sudo sh -c \"curl -fsSL $ADDY_INSTALLER_URL | sh\""
}

check_size() {
  local mem cpus disk root
  mem="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  cpus="$(nproc 2>/dev/null || echo 1)"
  # The docker data root, not /, because that is where the volumes land.
  root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
  [ -d "$root" ] || root=/var
  disk="$(df -Pk "$root" | awk 'NR==2 {print $4}')"

  [ "$mem" -ge "$ADDY_MIN_MEM_KB" ] || refuse \
    "This box has $((mem/1024)) MiB of RAM. addy needs at least 2 GiB." \
    "Resize the VPS. Garage memory-maps its LMDB metadata store and addy holds \
relay buffers per session; 1 GiB boxes OOM under the first concurrent upload."

  [ "$cpus" -ge "$ADDY_MIN_CPUS" ] || refuse \
    "This box has $cpus vCPU. addy needs at least 2." \
    "Resize the VPS. One core is shared between TLS termination, SRTP/DTLS in \
the TURN path and Garage's background scrubber, and they contend."

  [ "$disk" -ge "$ADDY_MIN_DISK_KB" ] || refuse \
    "Only $((disk/1024/1024)) GiB free on $root. addy needs at least 20 GiB." \
    "Attach or grow a volume at $root."
}

check_docker() {
  command -v docker >/dev/null 2>&1 || refuse \
    "Docker is not installed." \
    "curl -fsSL https://get.docker.com | sh   (then re-run this installer)"

  docker info >/dev/null 2>&1 || refuse \
    "Docker is installed but the daemon is not reachable." \
    "systemctl start docker"

  # `docker compose` (the plugin, v2) and `docker-compose` (the retired Python
  # v1) are different programs with different YAML support. v1 does not
  # understand `depends_on: {condition: service_healthy}` in the v2 schema and
  # will silently start addy before Garage can take a PUT. Require the plugin.
  docker compose version >/dev/null 2>&1 || refuse \
    "The Docker Compose v2 plugin is missing. A standalone \`docker-compose\` \
binary is not a substitute: it ignores the healthcheck gate this deployment \
depends on." \
    "apt-get install docker-compose-plugin  (or the equivalent for this distro)"
}

# --- preflight: DNS is live, publicly, and points here ---------------------
#
# Deliberately NOT `getent hosts`. The local resolver answers from /etc/hosts,
# from a stale cache, and from a split-horizon view -- all three of which say
# yes while Let's Encrypt says no. The only question that matters is what a
# public resolver sees, so ask one over DoH, and compare it to what a public
# echo says this box's address is.

public_ip() {  # $1 = -4 or -6
  curl "$1" -fsS --max-time 10 https://www.cloudflare.com/cdn-cgi/trace \
    | awk -F= '/^ip=/ {print $2}'
}

doh_resolve() { # $1 = name, $2 = A|AAAA
  curl -fsS --max-time 10 -H 'accept: application/dns-json' \
    "https://dns.google/resolve?name=$1&type=$2" \
    | grep -o "\"data\":\"[^\"]*\"" | cut -d'"' -f4
}

check_dns() {
  local domain="$1" v4 v6 a aaaa
  v4="$(retry_network "detecting public IPv4" public_ip -4 || true)"
  v6="$(retry_network "detecting public IPv6" public_ip -6 || true)"
  [ -n "$v4$v6" ] || refuse \
    "Could not determine this box's public IP address." \
    "Check outbound HTTPS works, then re-run."

  a="$(retry_network "resolving A $domain" doh_resolve "$domain" A || true)"
  aaaa="$(retry_network "resolving AAAA $domain" doh_resolve "$domain" AAAA || true)"

  [ -n "$a$aaaa" ] || refuse \
    "$domain does not resolve from a public resolver. certmagic's HTTP-01 \
challenge needs DNS to be live AT INSTALL TIME, not eventually." \
    "Create an A record for $domain pointing at ${v4:-this box} and wait for \
the TTL, then re-run."

  if [ -n "$a" ] && [ -n "$v4" ] && ! printf '%s\n' "$a" | grep -qx "$v4"; then
    refuse "$domain resolves to $(printf '%s' "$a" | tr '\n' ' ')but this box is $v4." \
           "Point the A record at $v4, or install on the box that owns that address."
  fi

  # An AAAA record is a positive statement that IPv6 works. Let's Encrypt
  # PREFERS AAAA when it exists and does not silently fall back to A on a
  # timeout. An AAAA left over from a previous host is therefore a total ACME
  # failure with an error that names neither IPv6 nor the stale record.
  if [ -n "$aaaa" ] && { [ -z "$v6" ] || ! printf '%s\n' "$aaaa" | grep -qx "$v6"; }; then
    refuse "$domain has an AAAA record ($(printf '%s' "$aaaa" | tr '\n' ' ')) \
that this box does not answer on. Let's Encrypt prefers IPv6 and will not fall \
back to IPv4 when the AAAA times out." \
      "Delete the AAAA record, or give this box working IPv6 at that address."
  fi
}

# --- preflight: port 80 is reachable FROM OUTSIDE --------------------------
#
# Stated honestly, because the alternative is a check that passes and a product
# that does not work: a shell on this box CANNOT prove inbound reachability by
# itself. Everything below rules out the causes that are visible from here --
# something already bound, or a local firewall -- and then hands the actual
# proof to `addy preflight`, which performs a real ACME HTTP-01 order against
# Let's Encrypt's STAGING directory. That is the only test that exercises the
# same path the real order will, and its error text is what distinguishes
# "provider firewall" from "wrong DNS" from "something else on :80".

check_port_free() {
  local busy
  busy="$(ss -Hltnp '( sport = :80 or sport = :443 )' 2>/dev/null || true)"
  [ -z "$busy" ] || refuse \
    "Something is already listening on port 80 or 443:
$busy
addy is the only thing that binds 80 and 443 -- it runs an SNI router there and
proxies everything else." \
    "Stop the other service (nginx, caddy, apache and traefik are the usual \
four), then re-run."
}

check_local_firewall() {
  # Informational, not a refusal: a local firewall that drops 80 is a cause we
  # can name, but its absence proves nothing about the provider's.
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw status | grep -qE '(^80|^443|Anywhere.*(80|443))' \
      || warn "ufw is active and has no rule for 80/443. It will be checked for real below."
    ufw status | grep -q "${ADDY_RELAY_MIN}:${ADDY_RELAY_MAX}/udp" \
      || warn "ufw is active and has no rule for ${ADDY_RELAY_MIN}:${ADDY_RELAY_MAX}/udp (TURN relay)."
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --list-ports 2>/dev/null | grep -q "${ADDY_RELAY_MIN}-${ADDY_RELAY_MAX}/udp" \
      || warn "firewalld is active and has no rule for ${ADDY_RELAY_MIN}-${ADDY_RELAY_MAX}/udp (TURN relay)."
  fi
}

check_acme_reachable() {  # $1 = domain
  local domain="$1"
  log "verifying port 80 is reachable from the internet (ACME staging order)"
  # Runs in the addy image, host-networked so it really binds this box's :80.
  # --staging keeps the production rate limit untouched; a staging order
  # exercises the identical HTTP-01 path.
  if ! docker run --rm --network host \
        -e ADDY_DOMAIN="$domain" \
        "ghcr.io/opsmaxx/addy:${ADDY_VERSION:-latest}" \
        preflight --http01 --staging; then
    refuse \
"An ACME HTTP-01 challenge for $domain did not complete. certmagic needs port 80
reachable from the internet, and this box cannot see why it is not.

The two causes a shell on this box cannot detect:
  * the VPS PROVIDER's firewall, which is a separate layer from the host's and
    is configured in their control panel, not here (AWS security groups, Hetzner
    Cloud firewalls, DigitalOcean cloud firewalls, Oracle Cloud's default
    ingress deny);
  * a network appliance in front of the box." \
    "Allow inbound TCP 80 and 443 in the provider's firewall as well as the \
host's, then re-run."
  fi
}

check_turn_relay() {
  # There is no honest shell-only inbound UDP test either, and this one is worse
  # than the TCP case: a TURN relay port receives packets that are unsolicited
  # from conntrack's point of view, so a STUN round trip proves nothing about
  # it. What CAN be proved locally is that the HOST firewall permits the range,
  # because traffic addressed to this box's own public IP still traverses the
  # INPUT chain. That is what `addy selftest --turn` does (section 4), and it is
  # run as the last step of the install rather than as a preflight, because it
  # needs the daemon up.
  log "TURN relay range ${ADDY_RELAY_MIN}-${ADDY_RELAY_MAX}/udp will be proved by selftest"
}

# --- install --------------------------------------------------------------

gen_env() {
  local domain="$1" email="$2" env_file="$INSTALL_DIR/.env"

  # THE re-runnability rule: .env is the source of truth and is never
  # regenerated. A regenerated GARAGE_DEFAULT_SECRET_KEY is not a fresh start,
  # it is a hard Garage startup error naming a key id (FINDING 1) -- and a
  # regenerated ADDY_TURN_SECRET invalidates every credential already issued to
  # a connected client.
  if [ -f "$env_file" ]; then
    log "keeping existing $env_file (re-run detected)"
    return 0
  fi

  log "generating secrets"
  umask 077                       # so the file is 0600 the moment it exists,
                                  # not 0600 after a chmod that a crash can miss
  cat > "$env_file" <<EOF
ADDY_DOMAIN=$domain
ADDY_ACME_EMAIL=$email
ADDY_VERSION=${ADDY_VERSION:-latest}

GARAGE_RPC_SECRET=$(openssl rand -hex 32)
GARAGE_DEFAULT_ACCESS_KEY=addy-$(openssl rand -hex 8)
GARAGE_DEFAULT_SECRET_KEY=$(openssl rand -hex 32)
GARAGE_DEFAULT_BUCKET=addy

ADDY_TURN_SECRET=$(openssl rand -hex 32)
ADDY_TURN_RELAY_MIN=$ADDY_RELAY_MIN
ADDY_TURN_RELAY_MAX=$ADDY_RELAY_MAX
EOF
  chmod 600 "$env_file"
}

fetch_bundle() {
  mkdir -p "$INSTALL_DIR"
  for f in docker-compose.yml garage.toml; do
    retry_network "downloading $f" \
      curl -fsSL "https://get.addy.example/$f" -o "$INSTALL_DIR/$f.new"
    mv "$INSTALL_DIR/$f.new" "$INSTALL_DIR/$f"
  done
  chmod 644 "$INSTALL_DIR/garage.toml"
}

start() {
  # Pull separately and retried, so a registry flake is a retry rather than a
  # half-started stack.
  retry_network "pulling images" docker compose -f "$INSTALL_DIR/docker-compose.yml" pull
  log "starting"
  docker compose -f "$INSTALL_DIR/docker-compose.yml" up -d --remove-orphans
}

mint_admin_token() {
  local env_file="$INSTALL_DIR/.env"
  grep -q '^GARAGE_ADMIN_TOKEN=' "$env_file" && return 0
  # -T because there is no TTY when this script is piped, and `compose exec`
  # without it fails with "the input device is not a TTY".
  local tok
  tok="$(docker compose -f "$INSTALL_DIR/docker-compose.yml" exec -T garage \
        /garage admin-token create --expires-in 365d \
        --scope ListBuckets,GetBucketInfo,ListKeys,GetKeyInfo,CreateKey,AllowBucketKey,DenyBucketKey,UpdateBucket \
        addy 2>/dev/null | awk '/^  [0-9a-f]{32}\./ {print $1}')" || true
  [ -n "$tok" ] && printf 'GARAGE_ADMIN_TOKEN=%s\n' "$tok" >> "$env_file"
  docker compose -f "$INSTALL_DIR/docker-compose.yml" up -d addy
}

main() {
  local domain="" email="" assume_yes=0

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --domain) domain="$2"; shift 2 ;;
      --email)  email="$2";  shift 2 ;;
      # Non-interactive mode. --yes alone is not enough: without a domain there
      # is nothing to ask certmagic for, so --yes REQUIRES --domain and says so
      # rather than prompting from a pipe that has no reader.
      --yes|-y) assume_yes=1; shift ;;
      --relay-range) ADDY_RELAY_MIN="${2%%-*}"; ADDY_RELAY_MAX="${2##*-}"; shift 2 ;;
      --help|-h) sed -n '2,30p' "$0"; exit 0 ;;
      *) refuse "Unknown option: $1" "install.sh --help" ;;
    esac
  done

  # Environment is the other half of non-interactive mode, for the config-
  # management case where passing flags through `curl | sh -s --` is awkward.
  domain="${domain:-${ADDY_DOMAIN:-}}"
  email="${email:-${ADDY_ACME_EMAIL:-}}"

  if [ -z "$domain" ]; then
    [ "$assume_yes" -eq 0 ] || refuse \
      "--yes was given without --domain." \
      "install.sh --yes --domain addy.example.com"
    # /dev/tty, not stdin: stdin is the installer script itself when piped.
    [ -e /dev/tty ] || refuse \
      "No domain given and no terminal to ask on." \
      "install.sh --yes --domain addy.example.com"
    printf 'Domain for this addy instance: ' > /dev/tty
    read -r domain < /dev/tty
  fi
  [ -n "$domain" ] || refuse "A domain is required." "install.sh --domain addy.example.com"

  check_root
  check_docker
  check_size
  check_port_free
  check_local_firewall
  check_dns "$domain"
  check_acme_reachable "$domain"
  check_turn_relay

  fetch_bundle
  gen_env "$domain" "$email"
  start
  mint_admin_token

  log "waiting for the relay to come up"
  docker compose -f "$INSTALL_DIR/docker-compose.yml" exec -T addy /addy selftest \
    || refuse "addy started but selftest failed. See: docker compose -f $INSTALL_DIR/docker-compose.yml logs addy"

  log "done — https://$domain"
}

main "$@"
```

### Re-runnability, summarised

Four rules, and they are the whole of it:

1. `.env` is generated once and never regenerated.
2. Every Garage write goes through `--single-node`/`--default-bucket`, which
   upstream already makes idempotent — the installer issues no `layout apply`,
   no `key create` and no `bucket create` of its own.
3. `docker compose up -d` is idempotent; `--remove-orphans` cleans a rename.
4. Preflights are pure reads, except the ACME staging order, which is rate-safe
   by virtue of being staging.

The one non-idempotent step left is `admin-token create`, guarded by the
`grep -q '^GARAGE_ADMIN_TOKEN='` on `.env`.

---

## 4. `addy selftest` — proving TURN relays a packet

"The daemon started" is proved by a pid. "TURN works" is proved by a byte making
the round trip through the allocation. Concretely:

1. **Mint a credential the way a client would.** Call the same
   `internal/turnauth` function the signalling path uses: username
   `<unix-ts+ttl>:<device-pub>`, password `base64(HMAC-SHA1(ADDY_TURN_SECRET, username))`.
   If selftest minted credentials its own way it would pass while production
   failed, which is the failure mode this test exists to catch.

2. **Build two `pion/webrtc` PeerConnections in-process, both with
   `ICETransportPolicy: webrtc.ICETransportPolicyRelay`.** This is the load-
   bearing line. Under `relay` policy pion discards host and server-reflexive
   candidates entirely and gathers only `relay` candidates. Both peers are in
   the same process on the same box, so without it they would trivially connect
   over loopback and the test would prove nothing at all. With it, the *only*
   path that can exist is: peer A → TURN allocation → peer B.

3. **Point them at the public address, not 127.0.0.1.** ICE servers are
   `turn:<ADDY_DOMAIN>:3478?transport=udp` and `turns:<ADDY_DOMAIN>:5349?transport=tcp`.
   Packets addressed to the box's own public IP are routed via `lo` but still
   traverse the host's `INPUT` chain, so a host firewall that drops the relay
   range **fails this test**. That is what makes selftest a real check on the
   firewall rather than a loopback formality. It does not and cannot cover the
   VPS provider's separate firewall; the output says so in one line.

4. **Open a DataChannel, send a nonce, require it back.** 32 bytes from
   `crypto/rand`, sent A→B, echoed B→A, compared. A five-second deadline on the
   whole exchange.

5. **Assert the path was actually relayed.** Belt and braces, because a future
   pion release changing policy semantics would otherwise turn this green while
   it silently went direct:

   ```go
   pair, err := pcA.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
   // require pair.Local.Typ == webrtc.ICECandidateTypeRelay
   // require pair.Remote.Typ == webrtc.ICECandidateTypeRelay
   ```

6. **Assert an allocation existed server-side.** The embedded `pion/turn`
   server's allocation count goes 0 → ≥1 → 0 across the test. Catches the case
   where a stale external coturn answered instead of the embedded server.

7. **Tear down without tripping the known deadlock.** `DESIGN.md` records it:
   never call `PeerConnection.Close()` from inside a pion callback
   (pion/webrtc#2404). selftest closes from the test goroutine, after the
   channel-close signal, and asserts the process goroutine count returns to its
   baseline — the same counter the design wants exported so a leak shows up as a
   graph rather than an OOM.

`--quick` (used as the compose healthcheck) runs steps 1–5 against
`127.0.0.1:3478` with a two-second deadline: it re-proves relaying every 30
seconds without re-exercising the firewall path or minting garbage on the public
interface. The full form runs once at install and on demand.

Failure output names which step failed, because "TURN failed" sends people to
the wrong layer every time:

```
addy selftest: FAIL at step 3 (ICE gathering)
  No relay candidate was gathered within 5s.
  TURN server:   turn:addy.example.com:3478
  Relay range:   49160-49360/udp
  Allocations:   0
  Most likely:   UDP 49160-49360 is denied inbound.
  Check BOTH the host firewall and the VPS provider's firewall -- they are
  separate layers and this box can only see the first.
```

---

## 5. What the installer gets wrong if nobody thinks about it

Ordered by how much time each one costs before anybody works out what happened.

**1. The provider firewall is a second, invisible firewall.** Hetzner Cloud
firewalls, AWS security groups, DigitalOcean cloud firewalls and Oracle Cloud's
default-deny ingress all live outside the box. `ufw status` says `ALLOW 80` and
the packet never arrives. Oracle's free tier is the worst case: it ships with
essentially everything but 22 denied, and the deny is in the VCN, not in
`iptables`. Nothing on the box can detect this, so the installer must *name it
as a possibility* in the failure text — which is why `check_acme_reachable`
refuses with a two-cause list rather than "port 80 unreachable".

**2. `curl | sh` does not run bash, and a truncated download runs anyway.** The
shebang is ignored on stdin, so it is dash on every Debian derivative:
`pipefail` is a syntax error, `[[` does not exist, arrays do not exist. And if
the connection drops at byte 4000, `sh` executes the first 4000 bytes. The
prologue in §3 fixes both; most installers in the wild fix neither.

**3. `docker-compose` is not `docker compose`.** The retired Python v1 is still
installed by default on plenty of images and still first on `PATH`. It does not
implement `depends_on: {condition: service_healthy}` from the v2 schema — it
ignores the condition and starts addy immediately, so addy's first S3 call hits
a Garage with no layout and fails in a way that looks like a credential problem.
Refuse on the plugin's absence rather than falling back.

**4. The Garage image has no shell.** `FROM scratch` (FINDING 8). Every
`healthcheck: test: ["CMD-SHELL", ...]`, every `curl -f .../health`, every
`docker exec garage sh` fails with an exec error, not the error you were
testing for. Use `["CMD", "/garage", "health", "-q"]`.

**5. Garage refuses to start on world-readable secret files.**
`allow_world_readable_secrets` defaults to `false` and Garage checks the mode of
anything named by `rpc_secret_file` / `admin_token_file`. A `curl`-written file
under the default `umask 022` is `0644`, and Garage exits at startup with a
permissions complaint that reads like a bug. Passing secrets by *environment*
from a `0600` `.env` sidesteps the check entirely — which is why §2 does that
and why `gen_env` sets `umask 077` **before** the redirect rather than
`chmod 600` after it (a crash between the two leaves a readable secret).

**6. Publishing a big UDP range melts the daemon.** `-p 49152-65535:49152-65535/udp`
is 16384 `docker-proxy` processes and 16384 NAT rules. Minutes of startup,
gigabytes of RSS, and on smaller boxes the daemon simply never finishes. Host
networking, or a range measured in hundreds.

**7. Docker's userland proxy rewrites UDP source addresses.** With
`userland-proxy: true`, TURN sees every client arriving from the proxy's
address, which breaks `CreatePermission` and channel binding — the allocation
succeeds and no data flows. Host networking avoids it; `"userland-proxy": false`
in `daemon.json` also fixes it by using DNAT, at the cost of a different set of
edge cases.

**8. Docker bypasses ufw.** Published ports are DNAT'd in the `DOCKER` chain,
which runs before `ufw`'s rules in `FORWARD`. An operator who "firewalled off"
Garage with `ufw deny 3900` finds it open to the internet. Binding to
`127.0.0.1:3900` rather than `3900` is what actually closes it, and is the only
form that is correct regardless of what the firewall says.

**9. IPv6, in both directions.** An AAAA record left over from a previous host
is the expensive one: Let's Encrypt prefers AAAA and does not fall back to A on
a timeout, so the ACME order fails with an error mentioning neither IPv6 nor the
record. In the other direction, the default Docker bridge is IPv4-only, so a box
*with* working IPv6 still cannot serve a bridge-networked container over it
without `enable_ipv6` plus `ip6tables` in `daemon.json`. Host networking for
addy sidesteps the second; only `check_dns` catches the first.

**10. SELinux relabels, or refuses.** On RHEL/Rocky/Fedora with SELinux
enforcing, a bind-mounted `./garage.toml:/etc/garage.toml:ro` is unreadable
inside the container — `container_t` cannot read `admin_home_t`. The fix is the
`:z` (shared) or `:Z` (private) suffix. `:Z` **relabels the host file in place**,
so applying it to a shared or system path is destructive; on a file the
installer created under `/opt/addy` it is safe. Named volumes (which is what
Garage's data and metadata use here) are labelled correctly by Docker already,
so only the two bind mounts need it. AppArmor on Ubuntu does not have this
problem for bind mounts but does block `ptrace` and some `mount` calls from
inside containers, which matters if a debugging step ever needs `nsenter`.

**11. `docker compose exec` without `-T` fails when piped.** "the input device
is not a TTY" — the installer runs from a pipe by definition, so every `exec`
in a `curl | sh` path needs `-T`. And never `docker compose run` against the
`garage` service to run a CLI command: `run` starts a *second* Garage process
against the same metadata directory, which at best fails on the LMDB lock and at
worst confuses the cluster about how many nodes exist. `exec` only.

**12. LMDB and the filesystem underneath.** `db_engine = "lmdb"` memory-maps
its file; that works on ext4/xfs and does not work on NFS, and on a box with
very little RAM the map plus Garage's block cache is what gets OOM-killed first.
This is the concrete reason behind the 2 GiB minimum, and the reason the
metadata volume should be a named volume on local disk rather than anything
network-attached.

**13. `--single-node` becomes a hard startup failure after a manual layout
change.** Layout version `> 1` → Garage refuses to start with
`--single-node` (FINDING 1). An operator who added a second node, or who ran
`layout apply` by hand once, now has a box that will not boot after the next
`install.sh`. The installer should detect it (`GetClusterLayout.version > 1`)
and switch to the explicit §1.2 path rather than emitting Garage's error, which
does not mention the installer at all.

**14. Time.** ACME orders and the TURN REST credential scheme both fail on a
skewed clock — the TURN username is a unix timestamp, so a box minutes fast
mints credentials that every client rejects as expired, or vice versa. A
one-line `timedatectl show -p NTPSynchronized --value` check costs nothing and
removes a whole category of "it works for me".

---

## Sources

All fetched 2026-09-17.

- [Garage quick start (v2.4.1 source)](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/doc/book/quick-start/_index.md) — `--single-node`/`--default-bucket`, and the manual `layout assign`/`apply` path
- [Garage administration API reference (v2.4.1 source)](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/doc/book/reference-manual/admin-api.md) — bearer auth, `garage json-api`, scoped `admin-token`, master tokens discouraged
- [Garage admin API v2 OpenAPI document](https://garagehq.deuxfleurs.fr/api/garage-admin-v2.json) — every endpoint path, request and response schema quoted above
- [Cluster layout management](https://garagehq.deuxfleurs.fr/documentation/operations/layout/) — the `1 + previous` version rule and the never-apply-twice warning
- [Configuration file reference](https://garagehq.deuxfleurs.fr/documentation/reference-manual/configuration/) — `rpc_secret`, `[admin]`, `replication_factor`, `allow_world_readable_secrets`
- [S3 compatibility](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/doc/book/reference-manual/s3-compatibility.md) — bucket policies missing → 501, versioning stub
- [Deployment on a cluster](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/doc/book/cookbook/real-world.md) — production config template, image name
- [`src/garage/server.rs` at v2.4.1](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/src/garage/server.rs) — `initial_config()`, the exact idempotency and refusal behaviour of `--single-node`
- [`src/garage/cli/structs.rs` at v2.4.1](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/src/garage/cli/structs.rs) — `ServerOpt`, `AssignRoleOpt`, `ApplyLayoutOpt`, `HealthOpt`
- [`src/model/key_table.rs` at v2.4.1](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/src/model/key_table.rs) — relaxed access-key validation
- [`src/garage/cli/remote/cluster.rs` at v2.4.1](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/src/garage/cli/remote/cluster.rs) — `garage health` exit-code semantics
- [Garage Dockerfile at v2.4.1](https://git.deuxfleurs.fr/Deuxfleurs/garage/raw/tag/v2.4.1/Dockerfile) — `FROM scratch`
- [Garage release notes v2.3.0 / v2.4.0 / v2.4.1](https://git.deuxfleurs.fr/api/v1/repos/Deuxfleurs/garage/releases) — PR #1329 (initial setup), #1262 (relaxed keys), #1373 (`garage health`)
