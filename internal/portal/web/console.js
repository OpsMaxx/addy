// Your console: your accounts, your devices, your invite.
//
// Nothing on this page belongs to anybody else, whoever is reading it. An
// operator sees exactly what a member sees, plus one link to a separate page.
// That split is the point — the page an ordinary person lands on after signing
// in should not present itself as an administration console, because it is not
// administering anything.

import { $, api, boot, bytes, cell, fail, shortId, when, wireMint } from './console-kit.js'

async function loadMine(canMint) {
  const { accounts } = await api('/admin/v1/my/accounts')
  const body = $('my-accounts')
  body.replaceChildren()

  const some = accounts.length > 0
  $('my-accounts-shell').hidden = !some
  $('stats').hidden = !some
  $('no-mine').hidden = some

  // An operator reading "ask whoever runs it" is being told to ask themselves.
  $('no-mine-text').textContent = canMint
    ? 'You have no accounts on this relay yet. Create an invite above, then paste it into OpsMaxx along with this relay’s address.'
    : 'You have no accounts on this relay yet. Ask whoever runs this relay for an invite, then paste it into OpsMaxx along with this relay’s address.'

  let devices = 0
  let used = 0
  for (const a of accounts) {
    devices += a.devices
    used += a.usedBytes
    const tr = document.createElement('tr')
    tr.append(shortId(a.accountId), cell(String(a.devices)), cell(bytes(a.usedBytes)), cell(when(a.createdAt)))
    body.append(tr)
  }

  // The whole of what this relay knows about you, in three numbers. Counted
  // from the same rows the table below shows, so the two cannot disagree.
  $('stat-accounts').textContent = String(accounts.length)
  $('stat-devices').textContent = String(devices)
  $('stat-stored').textContent = bytes(used)
}

/**
 * The invite button.
 *
 * A member may mint their own invite only where signup is open; the operator
 * always may. The SERVER enforces that — this is an affordance, not a boundary.
 * Which is exactly why the failure mode mattered: the button used to be hidden
 * by CSS and left unwired, so the one time the CSS did not hold, a member got a
 * button that did nothing at all.
 *
 * So: the button is REMOVED where it may not be used, and the prose says what
 * to do instead. A disabled button would be a smaller change and a worse
 * answer — it offers a capability that no action of the reader's can unlock,
 * and leaves them hunting for the setting that would.
 */
function wireMyInvite(canMint) {
  $('invite-blurb').textContent = canMint
    ? 'An invite creates one account, and only its first device needs one. Every machine after that is added by pairing from one that already works — both apps open, one shows a code, and you check the same seven emoji appear on each.'
    : 'An invite creates one account, and this relay does not hand them out automatically. Ask whoever runs it. Every machine after your first is added by pairing, which needs nothing from them.'

  if (!canMint) {
    $('mint-mine-row').remove()
    return
  }
  wireMint({
    button: $('mint-mine'),
    note: $('mint-mine-note'),
    out: $('invite-mine'),
    warn: $('invite-mine-warn'),
    path: '/admin/v1/my/invite'
  })
}

async function main() {
  const me = await boot()
  if (!me) return

  const canMint = me.operator || me.signup === 'open'
  $('mine').hidden = false
  wireMyInvite(canMint)

  if (me.operator) $('operator-door').hidden = false
  else $('operator-door').remove()

  await loadMine(canMint).catch(fail)
}

void main()
