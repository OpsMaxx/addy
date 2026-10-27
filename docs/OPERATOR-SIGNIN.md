# Setting up sign-in for the operator console

The console at `/admin` is where you create invites and look at accounts,
instead of SSHing in to run `addy invite`. It needs an identity provider. This
walks through Google; any provider with OIDC discovery works the same way, and
§6 covers the others.

**Read `ADMIN.md` first** if you have not. It says what an operator can and
cannot do, and the short version is: availability and identity power, never
confidentiality. The console cannot read anything, and it cannot add or remove
a device — those are signed by keys that only exist on the account's own
machines.

**Two rules before you start.**

1. **Sign in yourself, first, immediately after the restart.** The first
   person to sign in claims the relay and everybody after has to be them.
   Until you do that, anyone who can reach the console and has an account at
   your provider can claim it.
2. **The client secret is a credential.** Put it in an environment file or a
   systemd `EnvironmentFile`, not in a command line that lands in your shell
   history and in `ps`.

---

## 1. Make a Google Cloud project

<https://console.cloud.google.com/projectcreate>

A name only you will see. If you already have a project for something else,
use it — this adds no cost and no quota.

## 2. Configure the consent screen

**APIs & Services → OAuth consent screen**

- **User type:** `External`, unless you pay for Google Workspace and want to
  restrict it to your own domain, in which case `Internal` is better and skips
  the rest of this section.
- **App name:** whatever you want to see on the sign-in page. `addy` is fine.
- **User support email / developer contact:** your own address.
- **Scopes:** add none. The three this uses — `openid`, `email`, `profile` —
  are the non-sensitive defaults and need no configuration and no review.

**Then leave the publishing status on `Testing` and add yourself as a test
user.** This is the part worth knowing: a `Testing` app is limited to the test
users you list — which is a membership list you maintain by hand, and for a
relay whose users you know is exactly what you want. It also skips Google's
verification review entirely. If you want anybody at your provider to be able
to sign in, this is the setting to revisit. Publishing to `Production`
would mean a review you do not need for an app only you sign in to.

> The seven-day expiry that `Testing` imposes applies to **refresh tokens**.
> This implementation never asks for one — it exchanges the code, reads
> UserInfo once, and issues its own session — so it does not apply here.

## 3. Create the OAuth client

**APIs & Services → Credentials → Create credentials → OAuth client ID**

- **Application type:** `Web application`
- **Name:** anything
- **Authorised JavaScript origins:** leave empty. The code exchange happens on
  the server, so the browser never talks to Google with your client id.
- **Authorised redirect URIs:** add exactly one —

  ```
  https://YOUR-RELAY-DOMAIN/admin/callback
  ```

  For the relay at `addy.opsmaxx.dev` that is
  `https://addy.opsmaxx.dev/admin/callback`.

  **This has to match character for character.** No trailing slash, `https`
  not `http`, and the hostname the relay actually answers on. A mismatch is
  the commonest failure here and Google reports it as `redirect_uri_mismatch`
  on the sign-in page, which at least names itself.

Copy the **client ID** and **client secret**. The secret is shown once in a
useful form; Google keeps it retrievable, but treat it as a password.

## 4. Restart the relay with the three flags

**Put all three in the environment, not on the command line.** `systemd`
expands a `${VAR}` in `ExecStart` into the argv it executes, so a unit that
passes the secret as a flag puts it in `/proc/<pid>/cmdline` and in every `ps`
on the box — which is the thing an `EnvironmentFile` was chosen to avoid. The
flags still exist and still work; the environment is what you should use.

**Installed with `install.sh` (compose).** The three are already in
`/opt/addy/.env`, empty. Fill them in and recreate the container:

```
ADDY_OIDC_ISSUER=https://accounts.google.com
ADDY_OIDC_CLIENT_ID=<your client id>
ADDY_OIDC_CLIENT_SECRET=<your client secret>
```

```sh
cd /opt/addy && docker compose up -d addy
```

The compose file already runs with `-ui`. `.env` is mode `0600` and the
installer never rewrites it.

**Helm.** The secret goes in a Secret, not in values, which end up in the
release history in plain text:

```sh
kubectl create secret generic addy-oidc --from-literal=client-secret='<your client secret>'
helm upgrade addy deploy/helm/addy --reuse-values \
  --set oidc.issuer=https://accounts.google.com \
  --set oidc.clientID='<your client id>' \
  --set oidc.clientSecretName=addy-oidc
```

**The binary under systemd.** `/etc/addy.env`, mode `0600`, with the same
three lines, and `/etc/systemd/system/addy.service`:

```ini
[Service]
EnvironmentFile=/etc/addy.env
ExecStart=/usr/local/bin/addy serve \
  -domain addy.opsmaxx.dev \
  -data-dir /var/lib/addy \
  -ui
```

The console — its pages and its API — is served whenever the three sign-in
settings are, with or without `-ui`. `-ui` adds the rest of the public portal:
the front page and the paste reader. Turn it on (or `portal.enabled` in Helm)
only if you want those.

Check it worked:

```sh
tr '\0' ' ' < /proc/$(pgrep -x addy)/cmdline | grep -c oidc   # expect 0
```

### Who else may sign in

A relay is multi-user. Anybody who signs in through your provider gets their
own space: their sync groups, their roster entries, their bytes — and nothing
of anybody else's. `ADDY_SIGNUP` decides who may sign in, and who gets storage:
somebody who gets storage mints the invite for their own first device, without
you.

| Value | What it means |
|---|---|
| `invite` | **The default.** Anybody can sign in, but only people you admit from the console's People list get storage. Nobody with an account at your provider gets space here without your say-so. |
| `open` | Anybody who signs in gets storage. Right when the provider already *is* your membership list — Google Workspace `Internal`, or an Okta group. |
| `closed` | Nobody but you signs in. Existing members can no longer sign in, but their devices keep syncing: they hold the keys, and this page is not what makes them work. |

The console's *Who may sign in* card shows and changes the policy without a
restart; a value set there overrides `ADDY_SIGNUP`. Admitting somebody is the
**Admit** button beside them in the People list, shown while the policy is
`invite`; withdrawing it also cancels any invite they minted and have not yet
used. Switching to `closed` signs every member out of the console at once.
The policy is enforced on the server, not by hiding a button.

Whoever claimed the relay is its operator and is not subject to this — §5.

**All three or none.** With none, no admin route exists at all and the page
says to use the `addy` command — an unconfigured console is absent rather than
open. With one or two, addy refuses to start and names the ones missing.

The log line to look for:

```
operator portal: sign-in is configured issuer=https://accounts.google.com
  redirect=https://addy.opsmaxx.dev/admin/callback
```

If the redirect there does not match what you registered, fix one of them
before you go further.

## 5. Claim it

Open `https://YOUR-RELAY-DOMAIN/admin` and sign in. **Do this now, not later.**

You land on `/console`, your own space, showing your email and a *You run this
relay* card. Its **Operator console** link opens `/console/relay`, which is the
relay's:

- **Invite somebody who will not sign in** — hand the invite to whoever is
  setting up their first device. It is shown once, works once, and expires in
  24 hours by default. (The invite button on `/console` is for your own first
  device.)
- **Sync groups** — an identifier, a count of roster entries, bytes used, a
  quota. That is everything this relay knows. Roster entries are not devices:
  a removed device and a key rotation each add one.

To check the claim did what it should: sign in from a different Google account.
It is a member, not the operator: `/console` shows no *You run this relay*
card, and `/console/relay` says *"This relay is not yours to run"*. (With the
policy at `closed`, the sign-in itself is refused with *"this relay is not open
for sign-in; ask whoever runs it"*.)

### If you claim it with the wrong account

The claim is one row, and `addy unclaim` clears it. Stop the relay first, so
the wrong account's session ends with it; start it again and sign in as the
right account straight away:

```sh
# compose: the image has no shell, so run the binary in a one-off container
cd /opt/addy
docker compose stop addy
docker compose run --rm --no-deps addy unclaim
docker compose start addy

# Helm: clear it, then restart the pod to end the session
kubectl exec <release>-addy-0 -- /addy unclaim
kubectl delete pod <release>-addy-0

# the binary
addy unclaim -data /var/lib/addy
```

## 6. A provider that is not Google

Nothing here is Google-specific. Set `-oidc-issuer` to the issuer URL and the
rest is the same:

| Provider | Issuer |
|---|---|
| Google | `https://accounts.google.com` |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant>/v2.0` |
| Okta | `https://<your-org>.okta.com` |
| Auth0 | `https://<your-tenant>.auth0.com` |
| Keycloak | `https://<host>/realms/<realm>` |
| GitLab | `https://gitlab.com` |

The requirement is discovery at `<issuer>/.well-known/openid-configuration`
advertising an **authorization**, **token** and **userinfo** endpoint. The
relay refuses an issuer missing any of the three at startup of the sign-in
rather than at the callback, so you find out before a browser is involved.

GitHub is **not** on that list and cannot be: it is OAuth 2.0 without OIDC and
publishes no discovery document.

## 7. What can go wrong

| What you see | What it is |
|---|---|
| `redirect_uri_mismatch` on Google's page | §3 — the registered URI is not what the relay sent. Compare it against the `redirect=` in the startup log. |
| `/console/relay` says *This relay is not yours to run* | You are signed in as an account that did not claim it. If the claim was you on another account, see §5. |
| `that sign-in is no longer in progress` | A back button, a bookmarked callback, or a replayed redirect. Start at `/admin` again. |
| `that issuer does not advertise the endpoints this needs` | The issuer URL is wrong, or the provider is OAuth-only. §6. |
| The page says no sign-in is configured | None of the three reached the process. Check `.env` (or the unit's `EnvironmentFile`) and that the container was recreated, not just restarted. |
| addy exits with `operator sign-in is half configured` | One or two of the three are set; the message names the rest. |
| 404 on `/console` or `/admin` | None of the three sign-in settings reached the process, and `-ui` is off, so no pages are served at all. |

## 8. What this does not do

It does not manage devices, and that is not a gap.

Adding or removing a device is a signed entry in a hash-chained log, signed by
a key that exists only on the account's own machines. A browser session holds
no such key. For a web page to add a device, this server would have to hold
key material — which ends the end-to-end encryption that is the entire point
of running a relay you control.

So a device is added from OpsMaxx: an invite for the first one, pairing with
seven compared emoji for every one after, and the twelve-word recovery phrase
if they are all gone. The console can tell you a sync group's roster has four
entries. It cannot tell you which devices they name or what they are called,
and it cannot remove one.
