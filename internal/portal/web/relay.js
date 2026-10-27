// The operator console: every person and every sync group on this relay.
//
// Its own page, reached deliberately from your own console, because the two
// answer different questions. Signing in as an ordinary member of somebody
// else's relay should not land you on something that calls itself an
// administration console — and an operator who wants to administer one should
// have gone somewhere to do it.
//
// THIS PAGE TOUCHES NO KEY AND ASKS FOR NO PHRASE, like everything else the
// portal serves. What it can do is what somebody with SSH to this box can
// already do: mint an invite, look at accounts, set a quota, delete one. The
// device list belongs in OpsMaxx, where the keys are, and this page says so
// rather than offering a button that cannot work.

import { $, api, boot, bytes, cell, clearProblem, fail, shortId, when, wireMint } from './console-kit.js'

async function loadUsers(me) {
  const { users } = await api('/admin/v1/users')
  const body = $('users')
  body.replaceChildren()
  $('no-users').hidden = users.length > 1
  $('stat-people').textContent = String(users.length)

  // Everybody here sets up their own devices; this line says who is on the
  // list, not what they may do once they are. The card below changes it —
  // pointing at a command-line flag was wrong even before it moved, because
  // the person reading it is already holding the control.
  $('signup-note').textContent =
    me.signup === 'closed'
      ? 'Nobody new can sign in. The people below already have accounts and are unaffected.'
      : 'Anybody who can sign in to your identity provider can get an account here. Each of them sets up their own devices without needing you.'

  for (const u of users) {
    const tr = document.createElement('tr')

    const person = document.createElement('td')
    person.textContent = u.email || u.name || u.userId
    // COMPARED BY IDENTITY, NOT BY EMAIL. A provider need not return an email,
    // and where it does not every row compares equal to every other — a "you"
    // chip on all of them and a Block button on none. userId is (issuer,
    // subject) as the store keys it, which is the thing that is actually one
    // person.
    const isMe = u.userId === me.userId
    if (isMe) {
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
    if (!isMe) {
      const block = document.createElement('button')
      block.className = 'button ghost small' + (u.blocked ? '' : ' danger')
      block.textContent = u.blocked ? 'Unblock' : 'Block'
      const who = u.email || u.name || u.userId
      block.setAttribute('aria-label', `${u.blocked ? 'Unblock' : 'Block'} ${who}`)
      block.addEventListener('click', async () => {
        if (!u.blocked) {
          // Said in full: blocking stops somebody signing in and getting new
          // invites. It does not stop their devices syncing, because those
          // hold the keys and this relay was never what made the sync group
          // theirs.
          const groups = u.accounts === 1 ? 'sync group keeps' : 'sync groups keep'
          const ok = window.confirm(
            `Block ${who}?\n\n` +
              `They are signed out now and will not be able to sign in here or get new invites. ` +
              `Their ${u.accounts} existing ${groups} working — ` +
              `their devices hold the keys, and this relay is not what makes those groups theirs. ` +
              `To stop syncing, delete the sync group below.`
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
  const some = accounts.length > 0
  $('accounts-shell').hidden = !some
  $('no-accounts').hidden = some
  $('stat-accounts').textContent = String(accounts.length)
  $('stat-stored').textContent = bytes(accounts.reduce((n, a) => n + a.usedBytes, 0))

  for (const a of accounts) {
    const tr = document.createElement('tr')

    const owner = document.createElement('td')
    // `owner` is whatever names the person — email, else the provider's
    // name, else their id, the same order the People table uses — so an
    // empty one means exactly one thing: a group registered with an invite
    // from this page, which named nobody. Said in words rather than a dash,
    // because a dash read as "the owner has no email" as easily as "nobody".
    owner.textContent = a.owner || 'nobody'
    owner.className = a.owner ? '' : 'fine'
    if (!a.owner) owner.title = 'Created from an operator invite. Not linked to any sign-in, so only you can see or delete it.'

    const quota = cell(a.quotaBytes ? bytes(a.quotaBytes) : 'unlimited')

    const actions = document.createElement('td')
    actions.className = 'right'

    const setQuota = document.createElement('button')
    setQuota.className = 'button ghost small'
    setQuota.textContent = 'Quota'
    setQuota.setAttribute('aria-label', `Set the quota for sync group ${a.accountId}`)
    setQuota.addEventListener('click', async () => {
      const answer = window.prompt(
        'Quota in megabytes for this sync group. 0 means unlimited.',
        a.quotaBytes ? String(Math.round(a.quotaBytes / 1024 / 1024)) : '0'
      )
      if (answer === null) return
      const mb = Number(answer.trim())
      if (answer.trim() === '' || !Number.isFinite(mb) || mb < 0) {
        return fail(new Error(`“${answer}” is not a number of megabytes. The quota was left as it was.`))
      }
      try {
        clearProblem()
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
    del.setAttribute('aria-label', `Delete sync group ${a.accountId}`)
    del.addEventListener('click', async () => {
      // Said in full before it happens. This cannot decrypt anything first, so
      // there is no version of it that produces readable data for the person
      // losing it — their own devices are the only way to get anything out,
      // and after this there is nothing to get it out of.
      const ok = window.confirm(
        `Delete sync group ${a.accountId}?\n\n` +
          `Everything this relay holds for it goes: ${a.rosterEntries} ` +
          `roster entr${a.rosterEntries === 1 ? 'y' : 'ies'} and ${bytes(a.usedBytes)} of sealed data. ` +
          `This relay cannot read any of it, so it cannot be exported first, and it cannot be undone.\n\n` +
          `Their devices keep whatever is already on them.`
      )
      if (!ok) return
      try {
        clearProblem()
        await api(`/admin/v1/accounts/${encodeURIComponent(a.accountId)}`, { method: 'DELETE' })
        await refreshAll(me)
      } catch (err) {
        fail(err)
      }
    })
    actions.append(del)

    tr.append(shortId(a.accountId), owner, cell(String(a.rosterEntries)), cell(bytes(a.usedBytes)), quota, actions)
    body.append(tr)
  }
}

async function refreshAll(me) {
  await loadUsers(me)
  await loadAccounts(me)
}

/**
 * Who may sign in, changed from here rather than from the unit file.
 *
 * THIS IS THE ONLY THING IT DECIDES NOW. Everybody signed in sets up their own
 * devices and mints their own invite; that needs nothing from the operator, so
 * the policy governs the earlier question — who gets through the door at all.
 *
 * The buttons say which one is in force rather than being a pair of equal
 * options, because an operator arriving here needs to read the current state
 * before they need to change it.
 */
async function wireSignup() {
  const paint = (s) => {
    const open = s.signup !== 'closed'
    $('signup-state').textContent = open
      ? 'Anybody who can sign in to your identity provider can get an account on this relay.'
      : 'Nobody new can sign in. People who already have an account here are unaffected.'
    $('signup-open').disabled = open
    $('signup-closed').disabled = !open
    $('signup-source').textContent =
      s.signupSource === 'console'
        ? 'Set from this page. It overrides ADDY_SIGNUP in the environment, which says ' + s.envDefault + '.'
        : 'Taken from ADDY_SIGNUP in the environment. Changing it here overrides that, and survives a restart.'
  }

  const set = async (signup) => {
    $('signup-saved').textContent = 'Saving…'
    try {
      paint(await api('/admin/v1/settings?signup=' + encodeURIComponent(signup), { method: 'POST' }))
      $('signup-saved').textContent = 'Saved.'
    } catch (err) {
      $('signup-saved').textContent = ''
      fail(err)
    }
  }

  $('signup-open').addEventListener('click', () => set('open'))
  $('signup-closed').addEventListener('click', () => set('closed'))
  paint(await api('/admin/v1/settings'))
}

async function main() {
  const me = await boot()
  if (!me) return

  if (!me.operator) {
    // Nothing here is theirs. The console is removed rather than hidden: the
    // server would refuse every call it makes anyway, and a console that
    // renders and then fills with errors is a worse answer than one sentence.
    $('console').remove()
    $('not-operator').hidden = false
    return
  }

  $('console').hidden = false
  wireMint({
    button: $('mint'),
    note: $('mint-note'),
    out: $('invite'),
    warn: $('invite-warn'),
    path: '/admin/v1/invite?hours=24',
    plain: $('invite-plain'),
    plainLabel: $('invite-plain-label')
  })

  await refreshAll(me).catch(fail)
  await wireSignup().catch(fail)
}

void main()
