// The operator console.
//
// THIS PAGE TOUCHES NO KEY AND ASKS FOR NO PHRASE, like everything else the
// portal serves — see the package comment. What it can do is what a person
// with SSH to this box can already do: mint an invite, look at accounts, set a
// quota, delete one. The device list belongs in OpsMaxx, where the keys are,
// and this page says so rather than offering a button that cannot work.

const $ = (id) => document.getElementById(id)

function fail(err) {
  if (err instanceof SessionEnded) return sessionEnded()
  const p = $('problem')
  p.textContent = String(err && err.message ? err.message : err)
  p.hidden = false
}

/** Thrown when the server says nobody is signed in. Its own type, because the
 *  page reacts to it rather than printing it. */
class SessionEnded extends Error {}

async function api(path, init) {
  const resp = await fetch(path, { credentials: 'same-origin', ...init })
  if (resp.status === 204) return null
  const body = await resp.json().catch(() => ({}))
  if (resp.status === 401) throw new SessionEnded()
  if (!resp.ok) throw new Error(body.error || `${resp.status} ${resp.statusText}`)
  return body
}

/**
 * The session ended under an open tab.
 *
 * Sessions are in memory, so every upgrade of this relay ends them — and a tab
 * left open then shows a signed-in console over a server that has never heard
 * of it. The first thing clicked used to answer "sign in first" in small text
 * at the bottom of a page still naming the account it thought was signed in.
 */
function sessionEnded() {
  $('console').hidden = true
  $('unconfigured').hidden = true
  $('signed-out').hidden = false
  const note = $('signed-out-note')
  if (note) {
    note.textContent =
      'Your session ended — this relay was restarted, or you were signed in for more than eight hours. Sign in again to carry on.'
    note.hidden = false
  }
}

function bytes(n) {
  if (!n) return '0'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

function when(iso) {
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
function shortId(id) {
  const td = document.createElement('td')
  td.className = 'mono'
  td.title = id
  td.textContent = id.slice(0, 12) + '…'
  return td
}

function cell(text, cls) {
  const td = document.createElement('td')
  if (cls) td.className = cls
  td.textContent = text
  return td
}

// ---------------------------------------------------------------------------
// Anybody signed in: their own space
// ---------------------------------------------------------------------------

async function loadMine() {
  const { accounts } = await api('/admin/v1/my/accounts')
  const body = $('my-accounts')
  body.replaceChildren()
  $('no-mine').hidden = accounts.length > 0

  for (const a of accounts) {
    const tr = document.createElement('tr')
    tr.append(shortId(a.accountId), cell(String(a.devices)), cell(bytes(a.usedBytes)), cell(when(a.createdAt)))
    body.append(tr)
  }
}

function wireMyInvite(me) {
  const canMint = me.operator || me.signup === 'open'
  $('mint-mine').hidden = !canMint
  $('invite-blurb').textContent = canMint
    ? 'Only your first device needs an invite. Every machine after that is added by pairing from one that already works — both apps open, one shows a code, and you check the same seven emoji appear on each.'
    : 'Your first device needs an invite, and this relay does not hand them out automatically. Ask whoever runs it. Every machine after that is added by pairing, which needs nothing from them.'

  if (!canMint) return
  $('mint-mine').addEventListener('click', async () => {
    $('mint-mine').disabled = true
    $('mint-mine-note').textContent = 'Creating…'
    try {
      const { invite, hours } = await api('/admin/v1/my/invite', { method: 'POST' })
      $('invite-mine').textContent = invite
      $('invite-mine').hidden = false
      $('invite-mine-warn').hidden = false
      $('mint-mine-note').textContent = `Valid for ${hours} hours, and it works once.`
      await navigator.clipboard.writeText(invite).catch(() => undefined)
    } catch (err) {
      $('mint-mine-note').textContent = ''
      fail(err)
    } finally {
      $('mint-mine').disabled = false
    }
  })
}

// ---------------------------------------------------------------------------
// The operator: the whole relay
// ---------------------------------------------------------------------------

async function loadUsers(me) {
  const { users } = await api('/admin/v1/users')
  const body = $('users')
  body.replaceChildren()
  $('no-users').hidden = users.length > 1

  $('signup-note').textContent =
    me.signup === 'open'
      ? 'Anybody who can sign in to your provider can get an account here. Change it with -signup if that is wider than you meant.'
      : me.signup === 'closed'
        ? 'Nobody but you can sign in. Change it with -signup to let others.'
        : 'People can sign in and see their own space; an invite still comes from you. Use -signup open to let them make their own.'

  for (const u of users) {
    const tr = document.createElement('tr')

    const person = document.createElement('td')
    person.textContent = u.email || u.name || u.userId
    if (u.email === me.email) {
      const chip = document.createElement('span')
      chip.className = 'chip you'
      chip.textContent = 'you'
      person.append(chip)
    }
    if (u.blocked) {
      const chip = document.createElement('span')
      chip.className = 'chip blocked'
      chip.textContent = 'blocked'
      person.append(chip)
    }
    tr.append(person, cell(String(u.accounts)), cell(bytes(u.usedBytes)), cell(when(u.lastSeen)))

    const actions = document.createElement('td')
    actions.className = 'right'
    if (u.email !== me.email) {
      const block = document.createElement('button')
      block.className = 'button ghost small' + (u.blocked ? '' : ' danger')
      block.textContent = u.blocked ? 'Unblock' : 'Block'
      block.addEventListener('click', async () => {
        if (!u.blocked) {
          // Said in full: blocking stops somebody signing in and getting new
          // invites. It does not stop their devices syncing, because those
          // hold the keys and this relay was never what made the account
          // theirs.
          const ok = window.confirm(
            `Block ${u.email}?\n\n` +
              `They will not be able to sign in here or get new invites. ` +
              `Their ${u.accounts} existing account${u.accounts === 1 ? '' : 's'} keep working — ` +
              `their devices hold the keys, and this relay is not what makes those accounts theirs. ` +
              `To stop those, delete the accounts below.`
          )
          if (!ok) return
        }
        try {
          await api(`/admin/v1/users/${encodeURIComponent(u.userId)}/blocked?blocked=${!u.blocked}`, {
            method: 'POST'
          })
          await refreshAll(me)
        } catch (err) {
          fail(err)
        }
      })
      actions.append(block)
    }
    tr.append(actions)
    body.append(tr)
  }
}

async function loadAccounts(me) {
  const { accounts } = await api('/admin/v1/accounts')
  const body = $('accounts')
  body.replaceChildren()
  $('no-accounts').hidden = accounts.length > 0

  for (const a of accounts) {
    const tr = document.createElement('tr')

    const owner = document.createElement('td')
    // Blank rather than invented. An account registered with an invite that
    // named nobody belongs to nobody until somebody claims it, and writing
    // "unknown" would suggest the relay had lost track of something it never
    // knew.
    owner.textContent = a.owner || '—'
    owner.className = a.owner ? '' : 'fine'

    const quota = cell(a.quotaBytes ? bytes(a.quotaBytes) : 'unlimited')

    const actions = document.createElement('td')
    actions.className = 'right'

    const setQuota = document.createElement('button')
    setQuota.className = 'button ghost small'
    setQuota.textContent = 'Quota'
    setQuota.addEventListener('click', async () => {
      const answer = window.prompt(
        'Quota in megabytes for this account. 0 means unlimited.',
        a.quotaBytes ? String(Math.round(a.quotaBytes / 1024 / 1024)) : '0'
      )
      if (answer === null) return
      const mb = Number(answer)
      if (!Number.isFinite(mb) || mb < 0) return fail(new Error('That is not a number of megabytes.'))
      try {
        await api(
          `/admin/v1/accounts/${encodeURIComponent(a.accountId)}/quota?bytes=${Math.round(mb * 1024 * 1024)}`,
          { method: 'POST' }
        )
        await refreshAll(me)
      } catch (err) {
        fail(err)
      }
    })
    actions.append(setQuota)

    const del = document.createElement('button')
    del.className = 'button ghost small danger'
    del.textContent = 'Delete'
    del.addEventListener('click', async () => {
      // Said in full before it happens. This cannot decrypt anything first, so
      // there is no version of it that produces readable data for the person
      // losing it — their own devices are the only way to get anything out,
      // and after this there is nothing to get it out of.
      const ok = window.confirm(
        `Delete account ${a.accountId}?\n\n` +
          `Everything this relay holds for it goes: ${a.devices} device ` +
          `record${a.devices === 1 ? '' : 's'} and ${bytes(a.usedBytes)} of sealed data. ` +
          `This relay cannot read any of it, so it cannot be exported first, and it cannot be undone.\n\n` +
          `Their devices keep whatever is already on them.`
      )
      if (!ok) return
      try {
        await api(`/admin/v1/accounts/${encodeURIComponent(a.accountId)}`, { method: 'DELETE' })
        await refreshAll(me)
      } catch (err) {
        fail(err)
      }
    })
    actions.append(del)

    tr.append(shortId(a.accountId), owner, cell(String(a.devices)), cell(bytes(a.usedBytes)), quota, actions)
    body.append(tr)
  }
}

async function refreshAll(me) {
  await loadMine()
  if (!me.operator) return
  await loadUsers(me)
  await loadAccounts(me)
}

async function main() {
  let me
  try {
    me = await api('/admin/v1/me')
  } catch {
    // No route at all: this relay was started without the provider flags, so
    // there is no console rather than a broken one.
    $('unconfigured').hidden = false
    return
  }

  if (!me.signedIn) {
    $('signed-out').hidden = false
    return
  }

  $('who').textContent = me.email || 'this account'
  $('role').textContent = me.operator ? 'operator' : 'member'
  if (me.operator) $('role').classList.add('you')
  $('bar').hidden = false
  $('lede').textContent = me.operator
    ? 'You run this relay. It carries your users’ data between their devices and cannot read any of it.'
    : 'A relay you run yourself. It carries your data between your devices and cannot read any of it.'

  $('signout').addEventListener('click', async () => {
    await api('/admin/logout', { method: 'POST' }).catch(() => undefined)
    window.location.reload()
  })

  $('mine').hidden = false
  wireMyInvite(me)

  if (me.operator) {
    $('console').hidden = false
    $('mint').addEventListener('click', async () => {
      $('mint').disabled = true
      $('mint-note').textContent = 'Creating…'
      try {
        const { invite, hours } = await api('/admin/v1/invite?hours=24', { method: 'POST' })
        $('invite').textContent = invite
        $('invite').hidden = false
        $('invite-warn').hidden = false
        $('mint-note').textContent = `Valid for ${hours} hours, and it works once.`
        await navigator.clipboard.writeText(invite).catch(() => undefined)
      } catch (err) {
        $('mint-note').textContent = ''
        fail(err)
      } finally {
        $('mint').disabled = false
      }
    })
  }

  await refreshAll(me).catch(fail)
}

void main()
