// What both consoles need: the API call, the session, and the handful of
// formatters the tables use.
//
// THIS FILE TOUCHES NO KEY AND ASKS FOR NO PHRASE, like everything else the
// portal serves — see the package comment. What either console can do is what
// somebody with SSH to this box can already do.
//
// It is one file rather than two copies because the session rules are the part
// that must not drift: a 401 has to read the same on both pages, and a page
// that got it wrong would show a signed-in console over a server that has
// never heard of it.

export const $ = (id) => document.getElementById(id)

/** Thrown when the server says nobody is signed in. Its own type, because the
 *  page reacts to it rather than printing it. */
export class SessionEnded extends Error {}

export async function api(path, init) {
  const resp = await fetch(path, { credentials: 'same-origin', ...init })
  if (resp.status === 204) return null
  const body = await resp.json().catch(() => ({}))
  if (resp.status === 401) throw new SessionEnded()
  if (!resp.ok) {
    // The status rides along because the caller sometimes has to tell "this
    // relay has no sign-in configured" (404) from "the request failed", and
    // guessing wrong means the page tells a working relay's owner that their
    // provider is missing.
    const err = new Error(body.error || `${resp.status} ${resp.statusText}`)
    err.status = resp.status
    throw err
  }
  return body
}

export function fail(err) {
  if (err instanceof SessionEnded) return sessionEnded()
  const p = $('problem')
  p.textContent = String(err && err.message ? err.message : err)
  p.hidden = false
  // The tables are long enough that a message pinned to the bottom of the page
  // is a message nobody reads.
  p.scrollIntoView({ block: 'nearest' })
}

export function clearProblem() {
  const p = $('problem')
  p.textContent = ''
  p.hidden = true
}

/**
 * Render as signed out, and mean it.
 *
 * Everything a signed-in person sees is REMOVED rather than hidden. Hiding is
 * a CSS promise, and that promise has already been broken once here: `[hidden]`
 * was scoped to one page, author `display:` rules outranked the browser's, and
 * signed-out visitors got a "Sign out" button. A node that is gone cannot be
 * clicked whatever the stylesheet says.
 */
export function stripSignedIn() {
  for (const id of ['bar', 'mine', 'operator-door', 'console', 'not-operator']) {
    const el = $(id)
    if (el) el.remove()
  }
}

export function showSignedOut(note) {
  stripSignedIn()
  const signIn = $('signed-out')
  if (signIn) signIn.hidden = false
  if (note) {
    const n = $('signed-out-note')
    if (n) {
      n.textContent = note
      n.hidden = false
    }
  }
}

/**
 * The session ended under an open tab.
 *
 * Sessions are in memory, so every restart of this relay ends them — and a tab
 * left open then shows a signed-in console over a server that has never heard
 * of it. The first thing clicked used to answer "sign in first" in small text
 * at the bottom of a page still naming the account it thought was signed in.
 *
 * A RESTART IS NOT THE ONLY CAUSE, and naming only it misleads the one reader
 * for whom it matters most. Blocking somebody ends their live sessions on the
 * spot (EndAllFor in internal/operator), so a blocked member's open tab lands
 * here too — and telling them the relay restarted sends them to sign in again
 * and be refused with no idea why. The 401 carries no reason, deliberately, so
 * every cause is named and the one that needs a person comes last.
 */
function sessionEnded() {
  clearProblem()
  showSignedOut(
    'You have been signed out. This relay may have restarted, or you were signed in for more than eight hours — sign in again to carry on. If signing in is refused, whoever runs this relay has signed you out or no longer lets this account sign in; ask them.'
  )
}

/**
 * Work out who is reading the page and put the identity bar up.
 *
 * Returns null when there is nobody to render a console for; the page has
 * already been told what to show in that case and should simply stop.
 */
export async function boot() {
  let me
  try {
    me = await api('/admin/v1/me')
  } catch (err) {
    if (err.status === 404) {
      // No route at all: this relay was started without the provider flags,
      // so there is no console rather than a broken one. The signed-in
      // furniture goes with it — there is nothing to sign out of.
      stripSignedIn()
      $('unconfigured').hidden = false
      return null
    }
    // Anything else is a relay that DOES have a sign-in and could not answer.
    // Saying "no sign-in is configured" here would send its owner to fix a
    // provider that is fine.
    showSignedOut()
    fail(err)
    return null
  }

  if (!me.signedIn) {
    // Nothing is said here about the signup policy, however helpful it would
    // be to warn a stranger that a closed relay will refuse them: /admin/v1/me
    // withholds it from anonymous callers on purpose, because it tells whoever
    // asks whether this relay hands out accounts — a thing to enumerate across
    // relays. The refusal after the click is the cost of not answering that.
    showSignedOut()
    return null
  }

  // NAMED BY WHATEVER THE PROVIDER ACTUALLY GAVE. OIDC `email` is optional and
  // plenty of providers omit it, so a bar that only knew how to print an email
  // printed nothing. The same mistake one level down — comparing two people by
  // a field that can be empty for both — is what made every row of the
  // operator's People table claim to be the operator; see relay.js.
  $('who').textContent = me.email || me.name || me.userId || 'this account'
  const role = $('role')
  role.textContent = me.operator ? 'operator' : 'member'
  if (me.operator) role.classList.add('you')
  $('signout').addEventListener('click', async () => {
    await api('/admin/logout', { method: 'POST' }).catch(() => undefined)
    window.location.reload()
  })
  $('bar').hidden = false
  return me
}

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

export function bytes(n) {
  // '0 B', not '0'. The same function fills a table cell and a headline stat,
  // and a bare zero under the label "Sealed data" reads as a missing value
  // rather than as a quantity that is genuinely nothing.
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

export function when(iso) {
  if (!iso) return 'never'
  const then = new Date(iso)
  const mins = Math.round((Date.now() - then.getTime()) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  if (mins < 60 * 24) return `${Math.round(mins / 60)}h ago`
  return then.toLocaleDateString()
}

/** The first bytes only. The whole identifier means nothing to a reader and
 *  makes the table unreadable at the width most people have. */
export function shortId(id) {
  const td = document.createElement('td')
  td.className = 'mono'
  td.title = id
  td.textContent = id.slice(0, 12) + '…'
  return td
}

/**
 * Copies each column's header onto its cells as `data-label`, which is what
 * the narrow-screen stylesheet prints in front of a cell once the header row
 * is gone. Read from the header the page already has, so the two cannot
 * disagree; called after every fill, because a fill replaces the rows.
 */
export function labelCells(tbody) {
  const heads = [...tbody.closest('table').querySelectorAll('thead th')].map((th) => th.textContent.trim())
  for (const tr of tbody.rows) {
    ;[...tr.cells].forEach((td, i) => {
      if (heads[i]) td.dataset.label = heads[i]
    })
  }
}

export function cell(text, cls) {
  const td = document.createElement('td')
  if (cls) td.className = cls
  td.textContent = text
  return td
}

/**
 * Both consoles mint invites, and they mint them the same way. One function,
 * because the two mistakes worth not making twice are both here:
 *
 *   - the listener is attached BEFORE anything decides whether the button
 *     should exist, and a button that may not be used is removed rather than
 *     hidden. A visible button that does nothing is the bug this replaces.
 *   - the invite is shown BEFORE the clipboard is touched. `navigator.clipboard`
 *     is undefined outside a secure context, so reading through it throws where
 *     a relay is reached over plain http — and that throw used to be reported as
 *     "creating the invite failed" while the invite sat on screen, already
 *     spent.
 */

/**
 * The `opsmaxx://sync` link for THIS relay, carrying the address and nothing
 * else.
 *
 * Built from `location.origin`, so it names the relay the person is actually
 * looking at rather than whatever a configuration file thinks this box is
 * called. The client refuses a link whose relay is not https (except on
 * loopback, for a dev relay), has credentials in it, or carries a path — see
 * `parseAddyLink` in the client's `src/shared/addyLink.ts`, which is the other
 * half of this format and the only thing that decides whether a link is one.
 * `location.origin` satisfies all three by construction: it is scheme, host
 * and port, with no path and no userinfo to strip.
 *
 * AN ADDRESS IS NOT A CREDENTIAL. This link spends nothing, joins nothing and
 * chooses nothing — on the other side it fills the relay field and leaves the
 * fork between "set up", "join" and "recover" to the person. That is why it is
 * safe to put on a page beside a button, and an invite link is not.
 *
 * The invite form is this plus one parameter, so the half that has to agree
 * with the parser is written once.
 */
export function relayLink() {
  const r = new URL(location.origin)
  return `opsmaxx://sync?relay=${encodeURIComponent(`${r.protocol}//${r.host}`)}`
}

function inviteLink(invite) {
  return `${relayLink()}&invite=${encodeURIComponent(invite)}`
}

export function wireMint({ button, note, out, warn, path, plain, plainLabel, once }) {
  button.addEventListener('click', async () => {
    let shown = false
    button.disabled = true
    note.textContent = 'Creating…'
    clearProblem()
    try {
      const { invite, hours } = await api(path, { method: 'POST' })
      // THE TOKEN ALONE IS NOT ENOUGH TO ACT ON. A machine that has never
      // synced does not know this relay's address, and nothing on it does —
      // the person was expected to remember the hostname and type it into a
      // field before the token could be used at all. The link carries both.
      //
      // Both are offered because neither works everywhere: a link is one
      // click on a machine that has OpsMaxx installed, and a token is what
      // survives a chat window that mangles unknown schemes, a QR code, or a
      // phone call.
      out.textContent = inviteLink(invite)
      out.hidden = false
      warn.hidden = false
      note.textContent = `Valid for ${hours} hours, and it works once.`
      if (await copy(out.textContent)) note.textContent += ' Copied to your clipboard.'
      if (plain) {
        plain.textContent = invite
        plain.hidden = false
      }
      // HANDED IN, NOT LOOKED UP FROM A BUILT ID. Deriving the label's id from
      // the token's put the only reference to it inside a template string,
      // where nothing reading the page can find it — which is precisely how a
      // control becomes unreachable without anybody noticing. The contract
      // test refused it, correctly.
      if (plainLabel) plainLabel.hidden = false
      shown = true
    } catch (err) {
      note.textContent = ''
      fail(err)
    } finally {
      // A failure always gives the button back; a success does only where
      // the caller mints for more than one person.
      button.disabled = once === true && shown
    }
  })
}

/** Clipboard, or an honest false. `navigator.clipboard` is undefined outside a
 *  secure context, so a relay reached over plain http throws here rather than
 *  returning anything — and every caller has something to say instead. */
export async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
