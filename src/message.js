// Messages and announces: the LXMF-like layer.
//
// A message is sign-then-encrypt:
//   body   = CBOR map {1: [to addresses], 2: time ms, 3: title, 4: content, 5: fields, 6: receipt secret}
//            (the time is the sender's claim, shown to users; nothing here acts on it)
//   signed = COSE_Sign1 / COSE_Sign over body, protected kid = sender address
//   sealed = COSE_Encrypt0 to the recipient's ratchet (HPKE integrated, kid = ratchet id)
//            or, as an extra, one COSE_Encrypt shared by several recipients (HPKE-KE, no kids)
//
// An announce is a signed statement "this identity is here, and this is its ratchet":
//   COSE_Sign1 / COSE_Sign over CBOR map
//     {1: public keyset (full announces only), 2: sequence, 4: app data, 5: ratchet COSE_Key, 7: services}
//
// The sequence grows with every announce; it only orders one identity's own
// announces and is never compared with the local clock.

import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { concat, equal, isBytes, toHex, utf8 } from './bytes.js'
import { decode, encode } from './cbor.js'
import * as cose from './cose.js'
import { Identity, addressOf, signerOf } from './identity.js'
import { CoseError, Key } from './keys.js'
import { asProvider, checkRatchet } from './ratchet.js'

export const M_TO = 1
export const M_TIME = 2
export const M_TITLE = 3
export const M_CONTENT = 4
export const M_FIELDS = 5
export const M_RECEIPT = 6 // random secret; proving we know it proves we opened the message

export const RECEIPT_SECRET_SIZE = 16
export const RECEIPT_TAG_SIZE = 16

export const A_IDENTITY = 1
export const A_SEQUENCE = 2
export const A_APP_DATA = 4
export const A_RATCHET = 5
export const A_SERVICES = 7 // optional bitmask: 1 = propagation node

// unprotected Sign1/Sign header carrying the sender's public keyset
export const H_IDENTITY = -65537

// a shared COSE_Encrypt names no ratchet, so receivers trial-decrypt: cap the work
export const MAX_TRIAL_RATCHETS = 16

export const nowMs = () => Date.now()

export class Message {
  constructor({ sender, recipients, timestamp, title = '', content = '', fields = new Map(), id = new Uint8Array(), signed = new Uint8Array(), ratchetId = null, receiptSecret = null, linkId = null }) {
    this.sender = sender
    this.recipients = recipients
    this.timestamp = timestamp
    this.title = title
    this.content = content
    this.fields = fields
    this.id = id
    this.signed = signed
    this.ratchetId = ratchetId // id of our ratchet it was sealed to
    this.receiptSecret = receiptSecret // the sender wants receiptTag(secret, our address) back
    this.linkId = linkId // set when it came over a link (authenticated by the link key, not signed)
  }

  get time() {
    return new Date(Number(this.timestamp))
  }
}

// we opened a message but do not have its sender's keyset (yet)
export class SenderUnknown extends CoseError {
  constructor(address) {
    super(`unknown sender ${toHex(address)}`)
    this.name = 'SenderUnknown'
    this.address = address
  }
}

// a short announce from an identity whose keyset we do not have yet
export class KeysetNeeded extends CoseError {
  constructor(address) {
    super(`need the keyset for ${toHex(address)}`)
    this.name = 'KeysetNeeded'
    this.address = address
  }
}

export function messageId(signed) {
  return sha256(signed)
}

// what `recipient` sends back to show it opened the message carrying `secret`
export function receiptTag(secret, recipient) {
  return hmac(sha256, secret, concat(utf8('cosechat receipt'), recipient)).slice(0, RECEIPT_TAG_SIZE)
}

const isEmpty = (c) => c === '' || c == null || (isBytes(c) && c.length === 0)
const hasFields = (f) => f && (f instanceof Map ? f.size : Object.keys(f).length)

function body({ to, timestamp, title, content, fields, receiptSecret }) {
  const b = new Map()
  if (to) b.set(M_TO, to)
  b.set(M_TIME, timestamp ?? nowMs())
  if (title) b.set(M_TITLE, title)
  if (!isEmpty(content)) b.set(M_CONTENT, content)
  if (hasFields(fields)) b.set(M_FIELDS, fields)
  if (receiptSecret != null) {
    if (!isBytes(receiptSecret) || receiptSecret.length !== RECEIPT_SECRET_SIZE) throw new Error(`receipt secret must be ${RECEIPT_SECRET_SIZE} bytes`)
    b.set(M_RECEIPT, receiptSecret)
  }
  return b
}

export { body as messageBody }

// the signed layer only (a Message with .signed set); seal it with envelope()
export function signMessage(sender, recipients, { content = '', title = '', fields = null, timestamp = null, attachIdentity = false, receiptSecret = null } = {}) {
  if (!recipients.length) throw new Error('no recipients')
  const b = body({ to: recipients.map((r) => r.address), timestamp, title, content, fields, receiptSecret })
  const u = attachIdentity ? new Map([[H_IDENTITY, sender.publicBytes]]) : null
  const signed = sender.sign(encode(b), u)
  return new Message({ sender: sender.address, recipients: b.get(M_TO), timestamp: b.get(M_TIME), title, content, fields: fields || new Map(), id: messageId(signed), signed, receiptSecret })
}

// COSE_Encrypt0 of a signed message to a recipient's ratchet (kid = ratchet id)
export function envelope(signed, ratchet) {
  checkRatchet(ratchet)
  return cose.encrypt0(signed, ratchet, { includeKid: true })
}

function ratchetFor(ratchets, r) {
  const rk = typeof ratchets === 'function' ? ratchets(r.address) : ratchets?.get(r.address)
  if (!rk) throw new Error(`no ratchet for ${toHex(r.address)}: it has to announce one`)
  return rk
}

// Sign and encrypt one sealed message for all recipients: { sealed, message }.
// `ratchets` maps a recipient address to its announced ratchet (a function or
// a BytesMap). One recipient gives COSE_Encrypt0 unless integrated is false;
// several share one COSE_Encrypt (an extra: a node uses sealEach).
export function seal(sender, recipients, opts = {}) {
  const m = signMessage(sender, recipients, opts)
  const { ratchets, integrated = true } = opts
  if (recipients.length === 1 && integrated) return { sealed: envelope(m.signed, ratchetFor(ratchets, recipients[0])), message: m }
  const keys = recipients.map((r) => {
    const rk = ratchetFor(ratchets, r)
    checkRatchet(rk)
    return new Key(rk.alg, rk.pub) // no kid: shared envelopes do not name recipients
  })
  return { sealed: cose.encrypt(m.signed, keys), message: m }
}

// sign once, then one COSE_Encrypt0 per recipient: { sealed: [[address, bytes]], message }
export function sealEach(sender, recipients, opts = {}) {
  const m = signMessage(sender, recipients, opts)
  return { sealed: recipients.map((r) => [r.address, envelope(m.signed, ratchetFor(opts.ratchets, r))]), message: m }
}

// { signed, rid }: the signed bytes and the id of the ratchet that opened it
export function open(env, ratchets) {
  const p = asProvider(ratchets)
  if (env.kind === 'Encrypt0') {
    const rid = env.unprotected.get(cose.H_KID)
    if (rid == null) throw new CoseError('sealed message names no ratchet')
    const rk = isBytes(rid) ? p.get(rid) : null
    if (!rk) throw new CoseError('sealed to a ratchet we no longer have (or never had)')
    return { signed: cose.decrypt0(env, rk), rid }
  }
  if (env.kind === 'Encrypt') {
    for (const rk of p.keys().slice(0, MAX_TRIAL_RATCHETS)) {
      try {
        return { signed: cose.decrypt(env, rk), rid: rk.kid }
      } catch {}
    }
    throw new CoseError('none of our recent ratchets opens this message')
  }
  throw new CoseError(`COSE_${env.kind} is not a sealed message`)
}

export function receiptSecretOf(v) {
  return isBytes(v) && v.length === RECEIPT_SECRET_SIZE ? v : null
}

// decrypt with one of our ratchets and verify the sender. `resolve(address)`
// returns the sender's public identity or null.
export function unseal(me, sealed, resolve, ratchets = null) {
  const { signed, rid } = open(cose.decode(sealed), ratchets)
  const sm = cose.decode(signed)
  const senderAddr = signerOf(sm)
  if (!senderAddr) throw new CoseError('message has no sender kid')
  let sender = resolve(senderAddr) || attached(sm, senderAddr)
  if (!sender) throw new SenderUnknown(senderAddr)
  if (!equal(sender.address, senderAddr)) throw new CoseError('resolved identity does not match sender address')
  const b = decode(sender.verify(sm))
  if (!(b instanceof Map)) throw new CoseError('message body is not a map')
  const to = b.get(M_TO) ?? []
  if (!Array.isArray(to) || !to.some((a) => equal(a, me.address))) throw new CoseError('message was not addressed to us')
  return new Message({
    sender: senderAddr,
    recipients: to,
    timestamp: b.get(M_TIME) ?? 0,
    title: b.get(M_TITLE) ?? '',
    content: b.get(M_CONTENT) ?? '',
    fields: b.get(M_FIELDS) ?? new Map(),
    id: messageId(signed),
    signed,
    ratchetId: rid,
    receiptSecret: receiptSecretOf(b.get(M_RECEIPT))
  })
}

function attached(sm, senderAddr) {
  const data = sm.unprotected.get(H_IDENTITY)
  if (isBytes(data) && equal(addressOf(data), senderAddr)) return Identity.fromBytes(data)
  return null
}

export function attachedIdentity(signed) {
  const sm = cose.decode(signed)
  const s = signerOf(sm)
  return s ? attached(sm, s) : null
}

// --- announces ---

export class Announce {
  constructor(identity, sequence, ratchet, appData = null, full = true, services = 0) {
    this.identity = identity
    this.sequence = sequence
    this.ratchet = ratchet
    this.appData = appData
    this.full = full // carried its keyset
    this.services = services
  }

  get address() {
    return this.identity.address
  }
}

// `sequence` must grow with each announce of this identity (default: Unix ms).
// full=false leaves out the keyset (receivers must already have it).
export function makeAnnounce(identity, ratchet, { appData = null, sequence = null, full = true, services = 0 } = {}) {
  const b = new Map([[A_SEQUENCE, sequence ?? nowMs()]])
  if (full) b.set(A_IDENTITY, identity.publicBytes)
  if (appData != null) b.set(A_APP_DATA, appData)
  checkRatchet(ratchet)
  b.set(A_RATCHET, ratchet.public().toCose())
  if (services) b.set(A_SERVICES, services)
  return identity.sign(encode(b))
}

// the address an announce claims (its signature kid), without verifying anything
export function announceAddress(data) {
  try {
    return signerOf(cose.decode(data))
  } catch {
    return null
  }
}

const isUint = (n) => (typeof n === 'number' && Number.isInteger(n) && n >= 0) || (typeof n === 'bigint' && n >= 0n)

// Check an announce: its keyset (included, or known(address) for a short one)
// hashes to the signed kid and to `address`, the signature verifies, and the
// ratchet is well formed. Throws KeysetNeeded for an unknown short announce.
export function verifyAnnounce(data, address = null, known = null) {
  const sm = cose.decode(data)
  const kid = signerOf(sm)
  if (!kid) throw new CoseError('announce without a kid')
  if (address && !equal(address, kid)) throw new CoseError('announce is for a different address')
  const b = decode(sm.content)
  if (!(b instanceof Map)) throw new CoseError('announce body is not a map')
  const pub = b.get(A_IDENTITY)
  let ident
  if (pub !== undefined) {
    if (!isBytes(pub) || !equal(addressOf(pub), kid)) throw new CoseError('announce keyset does not match its kid')
    ident = Identity.fromBytes(pub)
  } else {
    ident = known ? known(kid) : null
    if (!ident) throw new KeysetNeeded(kid)
  }
  ident.verify(sm)
  if (!b.has(A_RATCHET)) throw new CoseError('announce has no ratchet')
  const ratchet = Key.fromCose(b.get(A_RATCHET))
  if (ratchet.hasPrivate) throw new CoseError('announced ratchet contains a private key')
  checkRatchet(ratchet)
  const seq = b.get(A_SEQUENCE) ?? 0
  if (!isUint(seq)) throw new CoseError('announce sequence must be an unsigned integer')
  const services = b.get(A_SERVICES) ?? 0
  if (!isUint(services)) throw new CoseError('bad announce services')
  return new Announce(ident, seq, ratchet, b.get(A_APP_DATA) ?? null, pub !== undefined, Number(services))
}
