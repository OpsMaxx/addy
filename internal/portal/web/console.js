// Your console: your accounts, your devices, your invite.
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
        await loadMine()
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
    : 'A second device joins by pairing with one you already have — no invite, and nothing to ask anybody for. This relay cannot do the joining part for you, because that is signed with a key it does not have. It can give you the one thing the new machine has no way of knowing.'

  // Pairing is the answer once there is something to pair with, so the button
  // would be offering the wrong one of the two.
  if (!first) {
    $('mint-mine-row').remove()
    showHandoff()
    return
  }

  // Nothing to pair WITH yet, so the steps would be describing a machine that
  // does not exist. Removed rather than hidden, for the reason the rest of
  // this page removes things: hiding is a promise the stylesheet has broken
  // here before.
  $('pair-steps').remove()

  wireMint({
    button: $('mint-mine'),
    note: $('mint-mine-note'),
    out: $('invite-mine'),
    warn: $('invite-mine-warn'),
    path: '/admin/v1/my/invite',
    plain: $('invite-mine-plain'),
    plainLabel: $('invite-mine-plain-label')
  })
}

/**
 * The handoff to a second machine, which is as far as this relay can take it.
 *
 * IT CANNOT ADD A DEVICE AND IT DOES NOT PRETEND TO. Adding one means signing
 * a roster entry with the account key; the key is on the devices and this
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
 * worse than none: spending a second invite starts a SEPARATE sync group with
 * its own key, which is the outcome this card exists to prevent. A `pair` link
 * is not ours to build either — its code and pairing id can only be minted by
 * a machine holding the account key, which is every machine except this one.
 * So the link fills a field and chooses nothing, and the format lives beside
 * the invite's in `console-kit.js` so the two cannot drift from the parser.
 *
 * The href is set here rather than written into the markup, because the markup
 * does not know what this relay is called — the same reason the address below
 * it is not hardcoded either.
 */
function showHandoff() {
  $('pair-steps').hidden = false
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
