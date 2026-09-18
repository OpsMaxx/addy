// The paste reader.
//
// THE KEY IS IN THE FRAGMENT AND THE SERVER NEVER SEES IT. Browsers do not
// send anything after `#`, so the process that stored this ciphertext cannot
// read it, and neither can anything in front of it -- a reverse proxy, a
// corporate TLS interceptor, an access log.
//
// The CSP is what keeps that true in the browser (see portal.go): a fragment
// is readable by any script on this origin, so the control is that no script
// the attacker injected is ever the one running.

'use strict'

// The sealed blob's layout. Fixed-width and checked, because a parser that
// guesses at lengths is a parser an attacker steers.
//
//   magic      6   "ADDYP1"
//   kdf        1   which password KDF was used
//   iters      4   big-endian, that KDF's cost
//   salt      16
//   nonce     12
//   tag       32   HMAC-SHA256 over everything before it plus the ciphertext
//   ciphertext rest
const MAGIC = 'ADDYP1'
const KDF_PBKDF2_SHA512 = 1
const HEADER = 6 + 1 + 4 + 16 + 12 + 32

const enc = new TextEncoder()
const dec = new TextDecoder()

const $ = (id) => document.getElementById(id)

function show(which) {
  for (const id of ['loading', 'ready', 'revealed', 'problem']) {
    $(id).hidden = id !== which
  }
}

function fail(title, detail) {
  $('problem-title').textContent = title
  $('problem-detail').textContent = detail
  show('problem')
}

function b64decode(s) {
  const raw = atob(s)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out
}

function b64urlDecode(s) {
  return b64decode(s.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (s.length % 4)) % 4))
}

/**
 * Derive the two keys.
 *
 * TWO KEYS FROM ONE SECRET, with distinct info labels, and the MAC is not
 * redundant with AES-GCM's own tag. GCM is not key-committing: for a given
 * ciphertext an attacker who chooses the key can produce a second key that
 * also authenticates, which turns "wrong password" into "different plaintext".
 * An independent HMAC over the whole blob commits to one key, and it is
 * checked BEFORE anything is decrypted.
 *
 * The password is stretched and mixed into the HKDF input rather than being a
 * flag the server checks. A server-gated password is a password the server can
 * turn off.
 */
async function deriveKeys(fragmentKey, password, salt, kdf, iters) {
  let passwordMaterial = new Uint8Array(32) // all-zero when there is no password
  if (password) {
    if (kdf !== KDF_PBKDF2_SHA512) {
      throw new Error(`this message uses password KDF ${kdf}, which this page does not know`)
    }
    const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, [
      'deriveBits'
    ])
    passwordMaterial = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-512', salt, iterations: iters }, base, 256)
    )
  }

  const ikm = new Uint8Array(fragmentKey.length + passwordMaterial.length)
  ikm.set(fragmentKey, 0)
  ikm.set(passwordMaterial, fragmentKey.length)

  const hkdfKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  const derive = async (label) =>
    new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(label) },
        hkdfKey,
        256
      )
    )

  return {
    encKey: await crypto.subtle.importKey('raw', await derive('addy-paste-enc-v1'), 'AES-GCM', false, [
      'decrypt'
    ]),
    macKey: await crypto.subtle.importKey(
      'raw',
      await derive('addy-paste-mac-v1'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    )
  }
}

async function open_(sealed, fragmentKey, password) {
  if (sealed.length < HEADER) throw new Error('that message is truncated')
  if (dec.decode(sealed.slice(0, 6)) !== MAGIC) throw new Error('that is not an addy message')

  const kdf = sealed[6]
  const view = new DataView(sealed.buffer, sealed.byteOffset)
  const iters = view.getUint32(7, false)
  const salt = sealed.slice(11, 27)
  const nonce = sealed.slice(27, 39)
  const tag = sealed.slice(39, 71)
  const ciphertext = sealed.slice(71)

  const { encKey, macKey } = await deriveKeys(fragmentKey, password, salt, kdf, iters)

  // BEFORE decrypting, never after. Everything except the tag itself is
  // covered, so the KDF identifier and its cost cannot be downgraded by
  // someone who can rewrite the blob.
  const signed = new Uint8Array(39 + ciphertext.length)
  signed.set(sealed.slice(0, 39), 0)
  signed.set(ciphertext, 39)
  if (!(await crypto.subtle.verify('HMAC', macKey, tag, signed))) {
    throw new Error('WRONG_KEY')
  }

  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, encKey, ciphertext)
  // The metadata is inside the ciphertext too. Encrypting the body and leaving
  // the filename in the clear is how a paste service tells you somebody sent
  // `id_rsa` without being able to tell you what was in it.
  return JSON.parse(dec.decode(plain))
}

async function main() {
  const id = location.pathname.split('/').filter(Boolean).pop()
  const fragment = location.hash.slice(1)
  if (!id || !fragment) {
    fail('This link is incomplete', 'The part after the # is missing, and it is the half that decrypts the message. Ask the sender to send the whole link.')
    return
  }

  let fragmentKey
  try {
    fragmentKey = b64urlDecode(fragment)
  } catch {
    fail('This link is damaged', 'The key in it is not readable. Chat apps sometimes cut long links; ask the sender to send it again.')
    return
  }

  // A GET, which never consumes. The reader has not asked for it yet.
  let status
  try {
    const resp = await fetch(`/v1/paste/${encodeURIComponent(id)}`, { cache: 'no-store' })
    status = { code: resp.status, body: await resp.json().catch(() => ({})) }
  } catch {
    fail('Could not reach the server', 'The relay did not answer. Try again in a moment.')
    return
  }

  if (status.code === 404) {
    fail('No such message', 'This link does not point at anything. It may have been mistyped, or it may be old enough that the relay no longer keeps a record of it.')
    return
  }
  if (status.code === 410 || status.body.state === 'gone') {
    // Distinct from 404 on purpose: the sender can tell "they read it" from "I
    // sent the wrong link".
    fail('This message has already been read', 'It was a one-time message and somebody has opened it. If that was not you, tell the sender.')
    return
  }
  if (status.code !== 200) {
    fail('The relay refused', 'It answered ' + status.code + '. If an operator has just reset this box, that is why.')
    return
  }

  const burns = status.body.burns === true
  $('ready-note').textContent = burns
    ? 'Someone sent you a one-time message.'
    : 'Someone sent you a message.'
  $('burn-warning').hidden = !burns
  show('ready')

  $('reveal').addEventListener('click', async () => {
    $('reveal').disabled = true
    const password = $('password').value

    let sealed
    try {
      // THE POST. This is the only thing that consumes, which is what stops a
      // chat client's preview fetch burning the message before the human sees
      // it.
      const resp = await fetch(`/v1/paste/${encodeURIComponent(id)}/burn`, {
        method: 'POST',
        cache: 'no-store'
      })
      if (resp.status === 410) {
        fail('This message has already been read', 'Somebody opened it between this page loading and you pressing the button.')
        return
      }
      if (!resp.ok) {
        fail('The relay refused', 'It answered ' + resp.status + '.')
        return
      }
      sealed = b64decode((await resp.json()).sealed)
    } catch {
      fail('Could not reach the server', 'The relay did not answer.')
      $('reveal').disabled = false
      return
    }

    let content
    try {
      content = await open_(sealed, fragmentKey, password)
    } catch (err) {
      if (err && err.message === 'WRONG_KEY') {
        // The message is gone from the server either way -- the POST consumed
        // it. Saying so matters: a reader who thinks they can retry will keep
        // trying a link that no longer exists.
        $('password-row').hidden = false
        fail(
          password ? 'That password is wrong' : 'This message needs a password',
          'The message has already been taken off the relay, so this page is the only chance to open it. Ask the sender for the password and for a new link.'
        )
        return
      }
      fail('That message could not be opened', String(err && err.message ? err.message : err))
      return
    }

    $('body').textContent = content.body || ''
    const bits = []
    if (content.filename) bits.push(content.filename)
    if (content.contentType) bits.push(content.contentType)
    $('revealed-meta').textContent = bits.join(' · ')
    $('revealed-meta').hidden = bits.length === 0
    show('revealed')

    // Out of the address bar, so a screenshot, a shoulder, or a browser's own
    // history does not carry the key. The message is already on screen; the
    // fragment has done its job.
    history.replaceState(null, '', location.pathname)
  })

  $('copy').addEventListener('click', () => {
    void navigator.clipboard.writeText($('body').textContent)
  })
}

void main()
