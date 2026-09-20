// The operator console.
//
// THIS PAGE TOUCHES NO KEY AND ASKS FOR NO PHRASE, like everything else the
// portal serves — see the package comment. What it can do is what a person
// with SSH to this box can already do: mint an invite, look at accounts, set a
// quota, delete one. The device list belongs in OpsMaxx, where the keys are,
// and this page says so rather than offering a button that cannot work.

const $ = (id) => document.getElementById(id)

function fail(err) {
  const p = $('problem')
  p.textContent = String(err && err.message ? err.message : err)
  p.hidden = false
}

async function api(path, init) {
  const resp = await fetch(path, { credentials: 'same-origin', ...init })
  if (resp.status === 204) return null
  const body = await resp.json().catch(() => ({}))
  if (!resp.ok) throw new Error(body.error || `${resp.status} ${resp.statusText}`)
  return body
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

async function loadAccounts() {
  const { accounts } = await api('/admin/v1/accounts')
  const body = $('accounts')
  body.replaceChildren()
  $('no-accounts').hidden = accounts.length > 0

  for (const a of accounts) {
    const tr = document.createElement('tr')

    const id = document.createElement('td')
    // The first bytes only. The whole identifier is long, means nothing to a
    // reader, and makes the table unreadable at the width most people have.
    id.className = 'mono'
    id.title = a.accountId
    id.textContent = a.accountId.slice(0, 12) + '…'
    tr.append(id)

    const devices = document.createElement('td')
    devices.textContent = String(a.devices)
    tr.append(devices)

    const used = document.createElement('td')
    used.textContent = bytes(a.usedBytes)
    tr.append(used)

    const quota = document.createElement('td')
    // Zero means unlimited, and saying "0" would read as "no room left" —
    // which is the opposite.
    quota.textContent = a.quotaBytes ? bytes(a.quotaBytes) : 'unlimited'
    tr.append(quota)

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
      if (!Number.isFinite(mb) || mb < 0) return fail('That is not a number of megabytes.')
      try {
        await api(`/admin/v1/accounts/${encodeURIComponent(a.accountId)}/quota?bytes=${Math.round(mb * 1024 * 1024)}`, {
          method: 'POST'
        })
        await loadAccounts()
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
          `Everything this relay holds for it is removed: ${a.devices} device ` +
          `record${a.devices === 1 ? '' : 's'} and ${bytes(a.usedBytes)} of sealed data. ` +
          `This relay cannot read any of it, so it cannot be exported first, and ` +
          `it cannot be undone.\n\n` +
          `Their devices keep whatever is already on them.`
      )
      if (!ok) return
      try {
        await api(`/admin/v1/accounts/${encodeURIComponent(a.accountId)}`, { method: 'DELETE' })
        await loadAccounts()
      } catch (err) {
        fail(err)
      }
    })
    actions.append(del)

    tr.append(actions)
    body.append(tr)
  }
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
  $('console').hidden = false

  $('signout').addEventListener('click', async () => {
    await api('/admin/logout', { method: 'POST' }).catch(() => undefined)
    window.location.reload()
  })

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

  await loadAccounts().catch(fail)
}

void main()
