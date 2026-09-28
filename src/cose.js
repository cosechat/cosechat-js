// COSE message structures (RFC 9052) on top of cbor.js + keys.js.
//
//   sign1 / verifySign1       COSE_Sign1    single signer
//   sign / verifySign         COSE_Sign     multiple signers
//   mac0 / verifyMac0         COSE_Mac0     shared-key authentication
//   mac / verifyMac           COSE_Mac      MAC key delivered to recipients (HPKE-KE)
//   encrypt0 / decrypt0       COSE_Encrypt0 shared key (AEAD) or one recipient (HPKE integrated)
//   encrypt / decrypt         COSE_Encrypt  many recipients (HPKE-KE)
//
// All outputs are tagged CBOR. Every function taking a message accepts its
// bytes or an already decoded Message.

import { isBytes, randomBytes } from './bytes.js'
import { Tagged, decode as cborDecode, encode } from './cbor.js'
import { AeadAlg, CoseError, HmacAlg, HpkeAlg, SignAlg, getAlg, hpkeVariant } from './keys.js'

// header labels
export const H_ALG = 1
export const H_CRIT = 2
export const H_CTY = 3
export const H_KID = 4
export const H_IV = 5
export const H_PARTIAL_IV = 6
export const H_EK = -4 // COSE-HPKE encapsulated key

export const TAG_ENCRYPT0 = 16
export const TAG_MAC0 = 17
export const TAG_SIGN1 = 18
export const TAG_ENCRYPT = 96
export const TAG_MAC = 97
export const TAG_SIGN = 98

export const KINDS = {
  [TAG_ENCRYPT0]: 'Encrypt0',
  [TAG_MAC0]: 'Mac0',
  [TAG_SIGN1]: 'Sign1',
  [TAG_ENCRYPT]: 'Encrypt',
  [TAG_MAC]: 'Mac',
  [TAG_SIGN]: 'Sign'
}

const EMPTY = new Uint8Array()

function toMap(m) {
  if (m == null) return new Map()
  if (m instanceof Map) return new Map(m)
  return new Map(Object.entries(m).map(([k, v]) => [Number(k), v]))
}

function prot(m) {
  return m && m.size ? encode(m) : EMPTY
}

function unprot(b) {
  if (!b.length) return new Map()
  const m = cborDecode(b)
  if (!(m instanceof Map)) throw new CoseError('protected header is not a map')
  return m
}

// one header-carrying layer: a message body, a signer or a recipient
export class Layer {
  constructor(rawProtected, unprotected) {
    if (!isBytes(rawProtected) || !(unprotected instanceof Map)) throw new CoseError('malformed COSE headers')
    this.rawProtected = rawProtected
    this.unprotected = unprotected
    this.protected = unprot(rawProtected)
  }

  header(label) {
    if (this.protected.has(label)) return this.protected.get(label)
    return this.unprotected.get(label)
  }

  get alg() {
    return this.header(H_ALG)
  }

  get kid() {
    return this.header(H_KID)
  }
}

export class Message extends Layer {
  constructor(rawProtected, unprotected, kind, content) {
    super(rawProtected, unprotected)
    this.kind = kind
    this.content = content // payload (sign/mac) or ciphertext (encrypt)
    this.signature = null // Sign1 signature or Mac/Mac0 tag
    this.signers = [] // [[Layer, signature]]
    this.recipients = [] // [[Layer, ciphertext]]
  }
}

// parse a COSE message; untagged input is accepted when `expect` gives the tag
export function decode(data, expect = null) {
  try {
    return decodeInner(data, expect)
  } catch (e) {
    if (e instanceof CoseError) throw e
    throw new CoseError(`malformed COSE message: ${e.message}`)
  }
}

function decodeInner(data, expect) {
  const obj = isBytes(data) ? cborDecode(data) : data
  let tag, arr
  if (obj instanceof Tagged) {
    tag = obj.tag
    arr = obj.value
  } else if (expect != null) {
    tag = expect
    arr = obj
  } else {
    throw new CoseError('untagged COSE message')
  }
  if (!KINDS[tag] || !Array.isArray(arr)) throw new CoseError(`not a COSE message (tag ${tag})`)
  if (expect != null && tag !== expect) throw new CoseError(`expected COSE_${KINDS[expect]}, got COSE_${KINDS[tag]}`)
  const need = { [TAG_ENCRYPT0]: 3, [TAG_MAC0]: 4, [TAG_SIGN1]: 4, [TAG_ENCRYPT]: 4, [TAG_MAC]: 5, [TAG_SIGN]: 4 }[tag]
  if (arr.length !== need) throw new CoseError('wrong COSE array length')
  const m = new Message(arr[0], arr[1], KINDS[tag], arr[2])
  if (m.content !== null && !isBytes(m.content)) throw new CoseError('COSE content must be a byte string')
  if (tag === TAG_SIGN1 || tag === TAG_MAC0 || tag === TAG_MAC) m.signature = arr[3]
  const layers = (list) => {
    if (!Array.isArray(list)) throw new CoseError('malformed COSE layers')
    return list.map((s) => {
      if (!Array.isArray(s) || s.length !== 3) throw new CoseError('malformed COSE layer')
      return [new Layer(s[0], s[1]), s[2]]
    })
  }
  if (tag === TAG_SIGN) m.signers = layers(arr[3])
  if (tag === TAG_MAC) m.recipients = layers(arr[4])
  if (tag === TAG_ENCRYPT) m.recipients = layers(arr[3])
  return m
}

function asMessage(data, tag) {
  return data instanceof Message ? data : decode(data, tag)
}

function headers(alg, protectedH, unprotectedH, kid = null) {
  const p = new Map([[H_ALG, alg]])
  for (const [k, v] of toMap(protectedH)) p.set(k, v)
  const u = toMap(unprotectedH)
  if (kid != null) u.set(H_KID, kid)
  return [p, u]
}

function signAlg(key) {
  const a = key.algorithm
  if (!(a instanceof SignAlg)) throw new CoseError(`${a.name} is not a signature algorithm`)
  return a
}

const tagged = (tag, arr) => encode(new Tagged(tag, arr))

// --- Sign1 ---

export function sign1(payload, key, { protected: p0, unprotected: u0, externalAad = EMPTY, kidProtected = false } = {}) {
  const alg = signAlg(key)
  const [p, u] = headers(alg.id, p0, u0, kidProtected ? null : key.kid)
  if (kidProtected && key.kid != null) p.set(H_KID, key.kid)
  const rp = prot(p)
  const tbs = encode(['Signature1', rp, externalAad, payload])
  return tagged(TAG_SIGN1, [rp, u, payload, alg.sign(key, tbs)])
}

export function verifySign1(data, key, externalAad = EMPTY) {
  const m = asMessage(data, TAG_SIGN1)
  if (m.alg !== key.alg) throw new CoseError(`algorithm mismatch: message ${m.alg}, key ${key.alg}`)
  if (!isBytes(m.signature)) throw new CoseError('Sign1 signature must be a byte string')
  const tbs = encode(['Signature1', m.rawProtected, externalAad, m.content])
  if (!signAlg(key).verify(key, m.signature, tbs)) throw new CoseError('Sign1 signature is invalid')
  return m.content
}

// --- Sign (multiple signers) ---

export function sign(payload, keys, { protected: p0, unprotected: u0, externalAad = EMPTY } = {}) {
  const rp = prot(toMap(p0))
  const sigs = keys.map((key) => {
    const alg = signAlg(key)
    const sp = prot(new Map([[H_ALG, alg.id]]))
    const su = key.kid != null ? new Map([[H_KID, key.kid]]) : new Map()
    const tbs = encode(['Signature', rp, sp, externalAad, payload])
    return [sp, su, alg.sign(key, tbs)]
  })
  return tagged(TAG_SIGN, [rp, toMap(u0), payload, sigs])
}

// every key given must have produced a valid signature (hybrid: PQ and pre-quantum both hold)
export function verifySign(data, keys, externalAad = EMPTY) {
  const m = asMessage(data, TAG_SIGN)
  if (!keys.length) throw new CoseError('no verification keys')
  for (const key of keys) {
    let ok = false
    for (const [layer, sig] of m.signers) {
      if (layer.alg !== key.alg || !isBytes(sig)) continue
      if (layer.kid != null && key.kid != null && !sameBytes(layer.kid, key.kid)) continue
      const tbs = encode(['Signature', m.rawProtected, layer.rawProtected, externalAad, m.content])
      if (signAlg(key).verify(key, sig, tbs)) {
        ok = true
        break
      }
    }
    if (!ok) throw new CoseError(`no valid ${key.algorithm.name} signature`)
  }
  return m.content
}

function sameBytes(a, b) {
  if (!isBytes(a) || !isBytes(b) || a.length !== b.length) return false
  return a.every((x, i) => x === b[i])
}

// --- Mac0 / Mac ---

function macAlg(id) {
  const a = getAlg(id)
  if (!(a instanceof HmacAlg)) throw new CoseError(`${a.name} is not a MAC algorithm`)
  return a
}

export function mac0(payload, key, { protected: p0, unprotected: u0, externalAad = EMPTY } = {}) {
  const alg = macAlg(key.alg)
  const [p, u] = headers(alg.id, p0, u0, key.kid)
  const rp = prot(p)
  const tag = alg.tag(key.priv, encode(['MAC0', rp, externalAad, payload]))
  return tagged(TAG_MAC0, [rp, u, payload, tag])
}

export function verifyMac0(data, key, externalAad = EMPTY) {
  const m = asMessage(data, TAG_MAC0)
  if (m.alg !== key.alg) throw new CoseError(`algorithm mismatch: message ${m.alg}, key ${key.alg}`)
  if (!macAlg(key.alg).verify(key.priv, m.signature, encode(['MAC0', m.rawProtected, externalAad, m.content]))) throw new CoseError('Mac0 tag is invalid')
  return m.content
}

export function mac(payload, recipients, { alg = 5, protected: p0, unprotected: u0, externalAad = EMPTY, includeKid = false } = {}) {
  const a = macAlg(alg)
  const k = randomBytes(a.keySize)
  const [p, u] = headers(a.id, p0, u0)
  const rp = prot(p)
  const tag = a.tag(k, encode(['MAC', rp, externalAad, payload]))
  const rs = recipients.map((r) => wrapCek(k, a.id, r, includeKid))
  return tagged(TAG_MAC, [rp, u, payload, tag, rs])
}

export function verifyMac(data, key, externalAad = EMPTY) {
  const m = asMessage(data, TAG_MAC)
  const k = unwrapCek(m, key)
  if (!macAlg(m.alg).verify(k, m.signature, encode(['MAC', m.rawProtected, externalAad, m.content]))) throw new CoseError('Mac tag is invalid')
  return m.content
}

// --- recipients (COSE-HPKE key encryption) ---

function recipientInfo(nextAlg, rawProtected) {
  return encode(['HPKE Recipient', nextAlg, rawProtected, EMPTY])
}

function wrapCek(cek, nextAlg, key, includeKid) {
  const ke = hpkeVariant(key, false)
  const rp = prot(new Map([[H_ALG, ke.id]]))
  const { enc, ct } = ke.seal(key, cek, recipientInfo(nextAlg, rp), EMPTY)
  const u = new Map([[H_EK, enc]])
  if (includeKid && key.kid != null) u.set(H_KID, key.kid)
  return [rp, u, ct]
}

// trial-decrypt each recipient; recipients normally carry no kid, to hide who they are
function unwrapCek(m, key) {
  const ke = hpkeVariant(key, false)
  for (const [layer, ct] of m.recipients) {
    if (layer.alg !== ke.id) continue
    if (layer.kid != null && key.kid != null && !sameBytes(layer.kid, key.kid)) continue
    const enc = layer.header(H_EK)
    if (!isBytes(enc) || !isBytes(ct)) continue
    try {
      return ke.open(key, enc, ct, recipientInfo(m.alg, layer.rawProtected), EMPTY)
    } catch {}
  }
  throw new CoseError('no recipient entry could be opened with this key')
}

// --- Encrypt0 / Encrypt ---

function aeadAlg(id) {
  const a = getAlg(id)
  if (!(a instanceof AeadAlg)) throw new CoseError(`${a.name} is not a content encryption algorithm`)
  return a
}

// `key` is a shared AEAD key, or the recipient's HPKE public key (integrated mode).
// `iv` fixes the AEAD IV: only for byte-exact test vectors, never reuse one.
export function encrypt0(plaintext, key, { protected: p0, unprotected: u0, externalAad = EMPTY, includeKid = false, iv = null } = {}) {
  const kid = includeKid ? key.kid : null
  if (key.algorithm instanceof HpkeAlg) {
    const alg = hpkeVariant(key, true)
    const [p, u] = headers(alg.id, p0, u0, kid)
    const rp = prot(p)
    const { enc, ct } = alg.seal(key, plaintext, EMPTY, encode(['Encrypt0', rp, externalAad]))
    u.set(H_EK, enc)
    return tagged(TAG_ENCRYPT0, [rp, u, ct])
  }
  const alg = aeadAlg(key.alg)
  const [p, u] = headers(alg.id, p0, u0, kid)
  const rp = prot(p)
  iv = iv || randomBytes(alg.ivSize)
  u.set(H_IV, iv)
  const ct = alg.encrypt(key.priv, iv, plaintext, encode(['Encrypt0', rp, externalAad]))
  return tagged(TAG_ENCRYPT0, [rp, u, ct])
}

export function decrypt0(data, key, externalAad = EMPTY) {
  const m = asMessage(data, TAG_ENCRYPT0)
  const aad = encode(['Encrypt0', m.rawProtected, externalAad])
  const hpke = key.algorithm instanceof HpkeAlg
  const alg = hpke ? hpkeVariant(key, true) : aeadAlg(key.alg)
  if (m.alg !== alg.id) throw new CoseError(`algorithm mismatch: message ${m.alg}, key ${alg.id}`)
  try {
    if (hpke) {
      const enc = m.header(H_EK)
      if (!isBytes(enc)) throw new CoseError('no encapsulated key')
      return alg.open(key, enc, m.content, EMPTY, aad)
    }
    return alg.decrypt(key.priv, m.header(H_IV), m.content, aad)
  } catch (e) {
    throw new CoseError(`Encrypt0 decryption failed: ${e.message}`)
  }
}

export function encrypt(plaintext, recipients, { alg = 3, protected: p0, unprotected: u0, externalAad = EMPTY, includeKid = false } = {}) {
  const a = aeadAlg(alg)
  const cek = randomBytes(a.keySize)
  const iv = randomBytes(a.ivSize)
  const [p, u] = headers(a.id, p0, u0)
  u.set(H_IV, iv)
  const rp = prot(p)
  const ct = a.encrypt(cek, iv, plaintext, encode(['Encrypt', rp, externalAad]))
  const rs = recipients.map((r) => wrapCek(cek, a.id, r, includeKid))
  return tagged(TAG_ENCRYPT, [rp, u, ct, rs])
}

export function decrypt(data, key, externalAad = EMPTY) {
  const m = asMessage(data, TAG_ENCRYPT)
  const cek = unwrapCek(m, key)
  const a = aeadAlg(m.alg)
  try {
    return a.decrypt(cek, m.header(H_IV), m.content, encode(['Encrypt', m.rawProtected, externalAad]))
  } catch (e) {
    throw new CoseError(`Encrypt decryption failed: ${e.message}`)
  }
}
