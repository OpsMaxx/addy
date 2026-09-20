// Your console: your accounts, your devices, your invite.
//
// Nothing on this page belongs to anybody else, whoever is reading it. An
// operator sees exactly what a member sees, plus one link to a separate page.
// That split is the point — the page an ordinary person lands on after signing
// in should not present itself as an administration console, because it is not
// administering anything.

import { $, api, boot, bytes, cell, fail, shortId, when, wireMint } from './console-kit.js'

async function loadMine() {
  const { accounts } = await api('/admin/v1/my/accounts')
  const body = $('my-accounts')
  body.replaceChildren()

  const some = accounts.length > 0
  $('my-accounts-shell').hidden = !some
  $('stats').hidden = !some
  $('no-mine').hidden = some

  $('no-mine-text').textContent =
    'No devices on this relay yet. Create an invite above, then paste it into OpsMaxx along with this relay’s address to set up your first one.'

  let devices = 0
  let used = 0
  for (const a of accounts) {
    devices += a.devices
    used += a.usedBytes
    const tr = document.createElement('tr')
    tr.append(shortId(a.accountId), cell(String(a.devices)), cell(bytes(a.usedBytes)), cell(when(a.createdAt)))
    body.append(tr)
  }

  // DEVICES ARE WHAT A PERSON HAS; a sync group is an implementation detail
  // they only need when they have two. Counted from the same rows the table
  // below shows, so the two cannot disagree.
  $('stat-devices').textContent = String(devices)
  $('stat-stored').textContent = bytes(used)
  $('stat-groups').textContent = String(accounts.length)
  $('stat-groups-block').hidden = accounts.length < 2

  return accounts.length
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
function wireMyInvite(groups) {
  // WHAT AN INVITE DOES DEPENDS ON WHETHER YOU ALREADY HAVE A DEVICE, and
  // saying only one of the two is how somebody ends up with two sets of
  // devices that cannot see each other.
  //
  // With nothing yet, an invite sets up your first device — that is the
  // sign-up, and it is what the word means to most people asking for one.
  //
  // With a device already, the way to add another is PAIRING, which needs no
  // invite and no operator. Spending a second invite does not add to what you
  // have: it starts a separate group with its own key, and nothing syncs
  // between the two. The relay cannot merge them afterwards, because it holds
  // no key to either.
  const first = groups === 0
  $('mine-lead').textContent = first ? 'Set up your first device' : 'Add another device'
  $('invite-blurb').textContent = first
    ? 'An invite sets up your first device on this relay and creates the sync group it syncs into. Make one here — it needs nobody else — and paste it into OpsMaxx together with this relay’s address.'
    : 'Add it by pairing from a device you already have: open OpsMaxx on both, one shows a code, and you check that the same seven emoji appear on each. No invite, and nothing to ask anybody for.'

  // Pairing is the answer once there is something to pair with, so the button
  // would be offering the wrong one of the two.
  if (!first) {
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

  $('mine').hidden = false

  if (me.operator) $('operator-door').hidden = false
  else $('operator-door').remove()

  // The lead card cannot be written until the count is known, so the load
  // happens first and the card is wired from its answer. A card that rendered
  // "set up your first device" and then corrected itself would be worse than
  // one that waits.
  const groups = await loadMine().catch((err) => {
    fail(err)
    return null
  })
  if (groups === null) return
  wireMyInvite(groups)
}

void main()
