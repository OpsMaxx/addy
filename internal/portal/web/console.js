// Your console: your sync group, your devices, your invite.
//
// Nothing on this page belongs to anybody else, whoever is reading it. An
// operator sees exactly what a member sees, plus one link to a separate page.
// That split is the point — the page an ordinary person lands on after signing
// in should not present itself as an administration console, because it is not
// administering anything.

import { $, api, boot, bytes, cell, clearProblem, copy, fail, relayLink, shortId, when, wireMint } from './console-kit.js'

async function loadMine() {
  const { accounts } = await api('/admin/v1/my/accounts')
  const body = $('my-accounts')
  body.replaceChildren()

  const some = accounts.length > 0
  $('my-accounts-shell').hidden = !some
  $('stats').hidden = !some
  $('no-mine').hidden = some

  // The card above is re-drawn from the same count on every load (see
  // paintLead), so "above" is true whichever way the count went — including
  // straight after the delete below took it to zero.
  $('no-mine-text').textContent =
    'Nothing of yours is on this relay yet. Create an invite above and paste it into OpsMaxx: that sets up your first device and creates the group it syncs into.'

  let entries = 0
  let used = 0
  for (const a of accounts) {
    entries += a.rosterEntries
    used += a.usedBytes
    const tr = document.createElement('tr')
    // DELETING YOUR OWN SYNC GROUP, from the page you are already on.
    //
    // The route existed and nothing called it, which is the defect this
    // project keeps producing — a control implemented, tested and reachable
    // from nowhere. Somebody whose devices are all gone and who has no
    // recovery phrase has exactly one way forward, and it was an operator's
    // page they may not be able to open.
    const actions = document.createElement('td')
    actions.className = 'right'
    const del = document.createElement('button')
    del.className = 'button ghost small danger'
    del.textContent = 'Delete'
    del.setAttribute('aria-label', `Delete sync group ${a.accountId}`)
    del.addEventListener('click', async () => {
      // Said in full, because nothing here can be undone and nothing can be
      // read out first: this relay holds no key to any of it.
      const ok = window.confirm(
        `Delete this sync group?\n\n` +
          `${a.rosterEntries} roster entr${a.rosterEntries === 1 ? 'y' : 'ies'} and ` +
          `${bytes(a.usedBytes)} of sealed data go with it. This relay cannot read any of it, ` +
          `so it cannot be exported first, and it cannot be undone.\n\n` +
          `Any device still on this group keeps whatever is already on it, and stops syncing.`
      )
      if (!ok) return
      try {
        clearProblem()
        await api(`/admin/v1/my/accounts/${encodeURIComponent(a.accountId)}`, { method: 'DELETE' })
        // The count is what the lead card is drawn from, so it is redrawn
        // too: deleting your only group is exactly when the invite button has
        // to come back.
        paintLead(await loadMine())
      } catch (err) {
        fail(err)
      }
    })
    actions.append(del)

    tr.append(
      shortId(a.accountId),
      cell(String(a.rosterEntries)),
      cell(bytes(a.usedBytes)),
      cell(when(a.createdAt)),
      actions
    )
    body.append(tr)
  }

  // DEVICES ARE WHAT A PERSON HAS; a sync group is an implementation detail
  // they only need when they have two. Counted from the same rows the table
  // below shows, so the two cannot disagree.
  $('stat-devices').textContent = String(entries)
  $('stat-stored').textContent = bytes(used)
  $('stat-groups').textContent = String(accounts.length)
  $('stat-groups-block').hidden = accounts.length < 2

  return accounts.length
}

/**
 * The lead card, painted from the number of sync groups this person has.
 *
 * A member may mint their own invite where signup is open, or where it is
 * `invite` and the operator has admitted them; the operator always may. The
 * SERVER enforces that and says which in `me.mayMint` — this is an affordance,
 * not a boundary.
 *
 * IT IS PAINTED, NOT BUILT ONCE. The count changes under an open page in both
 * directions: deleting your only group takes it to zero, and the invite you
 * just made registers a device from OpsMaxx while this tab sits in the
 * background. The card used to be decided once at load and the losing half
 * REMOVED — so after a delete there was no invite button left to press, under
 * an empty state saying "create an invite above", and after a registration it
 * went on offering a first device to somebody who had one. So both halves
 * stay in the page and are hidden, and this runs after every load.
 *
 * Hiding is safe to rely on now: `[hidden]` beats every display rule in the
 * stylesheet, and console_contract_test.go fails the build if that stops
 * being true.
 */
function paintLead(groups, me) {
  // WHAT AN INVITE DOES DEPENDS ON WHETHER YOU ALREADY HAVE A DEVICE, and
  // saying only one of the two is how somebody ends up with two sets of
  // devices that cannot see each other.
  //
  // With nothing yet, an invite sets up your first device — that is the
  // sign-up, and it is what the word means to most people asking for one.
  //
  // With a device already, the way to add another is PAIRING, which needs no
  // invite and no operator. The store refuses a second group to somebody who
  // has one, so a button here would only ever fail.
  const first = groups === 0
  $('mine-lead').textContent = first ? 'Set up your first device' : 'Add another device'
  $('invite-blurb').textContent = first
    ? 'An invite sets up your first device on this relay and creates the sync group it syncs into. Make one here — it needs nobody else — and paste it into OpsMaxx together with this relay’s address.'
    : 'A second device joins by pairing with one you already have — no invite, and nothing to ask anybody for. This relay cannot do the joining part for you, because that is signed with a key it does not have. It can give you the one thing the new machine has no way of knowing.'

  // Not admitted: the button would be refused, so it is hidden and the
  // sentence says who to ask.
  const mayMint = me.mayMint === true
  if (first && !mayMint) {
    $('invite-blurb').textContent =
      'This relay gives storage to the people its operator admits, and you have not been admitted yet. Ask whoever runs it; once they have, this page lets you set up your first device without them.'
  }

  $('mint-mine-row').hidden = !first || !mayMint
  $('operator-made').hidden = !first
  $('pair-steps').hidden = first
  // An invite still on screen once a device has registered is spent: it
  // would only invite somebody to paste it a second time and be refused.
  if (!first) {
    for (const id of ['invite-mine', 'invite-mine-plain', 'invite-mine-plain-label', 'invite-mine-warn']) {
      $(id).hidden = true
    }
    $('mint-mine-note').textContent = ''
  }
}

/**
 * The handoff to a second machine, which is as far as this relay can take it.
 *
 * IT CANNOT ADD A DEVICE AND IT DOES NOT PRETEND TO. Adding one means signing
 * a roster entry with the sync group's key; the key is on the devices and this
 * server has never held a copy. What it can do is remove the step that
 * actually stops people, which is not the pairing and not the emoji: it is
 * that the joining machine is asked to name a relay, and nothing on that
 * machine knows the name. The person is expected to remember a hostname and
 * type it correctly before anything else can begin.
 *
 * `location.origin` rather than a configured hostname, so it names the relay
 * the reader is looking at rather than whatever a unit file believes this box
 * is called — the same reason the invite link is built that way. It has no
 * path and no credentials, which is what the client's link parser insists on.
 *
 * THE LINK CARRIES THE ADDRESS AND NOTHING ELSE. An invite in it would be
 * worse than none: the store refuses a second sync group to somebody who has
 * one, and an operator's invite would start a separate group with its own
 * key. A `pair` link is not ours to build either — its pairing code can only
 * be minted by a machine holding the group's key, which is every machine
 * except this one. So the link fills a field and chooses nothing, and the
 * format lives beside the invite's in `console-kit.js` so the two cannot drift
 * from the parser.
 *
 * Wired once, at load, whichever half of the card is showing: paintLead may
 * reveal it later without coming back here.
 */
function wireLead() {
  wireMint({
    button: $('mint-mine'),
    note: $('mint-mine-note'),
    out: $('invite-mine'),
    warn: $('invite-mine-warn'),
    path: '/admin/v1/my/invite',
    plain: $('invite-mine-plain'),
    plainLabel: $('invite-mine-plain-label')
  })

  $('relay-address').textContent = window.location.origin
  $('open-here').href = relayLink()
  const note = $('copy-relay-note')
  $('copy-relay').addEventListener('click', async () => {
    note.textContent = (await copy(window.location.origin))
      ? 'Copied.'
      : 'This browser would not let the page copy it — select it and copy by hand.'
  })
}

async function main() {
  const me = await boot()
  if (!me) return

  $('mine').hidden = false

  if (me.operator) $('operator-door').hidden = false
  else $('operator-door').remove()

  // The lead card cannot be written until the count is known, so the load
  // happens first and the card is painted from its answer. A card that rendered
  // "set up your first device" and then corrected itself would be worse than
  // one that waits.
  const groups = await loadMine().catch((err) => {
    fail(err)
    return null
  })
  if (groups === null) return
  wireLead()
  paintLead(groups, me)

  // COMING BACK TO THE TAB IS WHEN THE ANSWER CHANGES. The invite is pasted
  // into OpsMaxx, in another window; the device registers there; and the
  // person returns here to a card still saying "set up your first device"
  // over an empty table. `focus` covers switching back from another
  // application, `visibilitychange` switching back from another tab, and one
  // switch can fire both — so a load already in flight is reused rather than
  // doubled.
  let inFlight = null
  const refresh = () => {
    // Signed out underneath us: the session handler has already removed the
    // page this would be painting into.
    if (inFlight || !$('mine')) return
    inFlight = loadMine()
      .then((n) => paintLead(n, me))
      .catch(fail)
      .finally(() => {
        inFlight = null
      })
  }
  window.addEventListener('focus', refresh)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refresh()
  })
}

void main()
