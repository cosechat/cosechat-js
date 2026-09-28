// Identities and addresses.
//
// An identity is a COSE_KeySet of one or more signing keys. Its address is
// the first 16 bytes of SHA-256 over the deterministic CBOR encoding of the
// public keyset (keys carry no kid). Anyone holding the public keyset can
// check that it hashes to the address.
//
// An identity has no encryption key of its own: messages are sealed to a
// ratchet (ratchet.js), a KEM key the identity signs into its announces.

import { sha256 } from '@noble/hashes/sha2.js'
import { equal, isBytes } from './bytes.js'
import { decode, encode } from './cbor.js'
import * as cose from './cose.js'
import { CoseError, ED25519, HPKE_0, HPKE_9, Key, ML_DSA_65, QUANTUM_SAFE_SIGN, SignAlg } from './keys.js'

export const ADDRESS_SIZE = 16

// name -> [signing algs, KEM alg for its ratchets]
export const SUITES = {
  // ML-DSA-65 signatures, X-Wing (ML-KEM-768 + X25519) ratchets
  pq: [[ML_DSA_65], HPKE_9],
  // Ed25519 AND ML-DSA-65 (COSE_Sign, both must verify), X-Wing ratchets
  hybrid: [[ED25519, ML_DSA_65], HPKE_9],
  // small enough for single LoRa frames; not quantum-safe
  prequantum: [[ED25519], HPKE_0]
}

export function addressOf(publicBytes) {
  return sha256(publicBytes).slice(0, ADDRESS_SIZE)
}

export class Identity {
  constructor(signKeys, publicBytes = null) {
    if (!signKeys.length) throw new CoseError('identity needs at least one signing key')
    for (const k of signKeys) {
      if (!(k.algorithm instanceof SignAlg)) throw new CoseError(`${k.algorithm.name} is not a signature algorithm`)
    }
    this._sign = signKeys.map((k) => new Key(k.alg, k.pub, k.priv))
    // keep received bytes verbatim so the address never depends on re-encoding
    this.publicBytes = publicBytes || encode(this._sign.map((k) => k.toCose()))
    this.address = addressOf(this.publicBytes)
    this.signKeys = this._sign.map((k) => new Key(k.alg, k.pub, k.priv, this.address))
  }

  static generate(suite = 'pq') {
    if (!SUITES[suite]) throw new Error(`unknown suite ${suite}`)
    return new Identity(SUITES[suite][0].map((a) => Key.generate(a)))
  }

  equals(other) {
    return other instanceof Identity && equal(this.publicBytes, other.publicBytes)
  }

  // at least one PQ signing key (verifiers require every signature in the keyset)
  get quantumSafe() {
    return this.signKeys.some((k) => QUANTUM_SAFE_SIGN.has(k.alg))
  }

  // the KEM its own ratchets should use: X-Wing if it signs with ML-DSA
  get kemAlg() {
    return this.quantumSafe ? HPKE_9 : HPKE_0
  }

  get hasPrivate() {
    return this.signKeys.every((k) => k.hasPrivate)
  }

  public() {
    return new Identity(this._sign.map((k) => k.public()))
  }

  // COSE_KeySet. With priv=true this holds secrets: keep it safe.
  toBytes(priv = true) {
    if (!priv) return this.publicBytes
    return encode(this._sign.map((k) => k.toCose(true)))
  }

  static fromBytes(data) {
    const set = decode(data)
    if (!Array.isArray(set)) throw new CoseError('a keyset is a CBOR array')
    const keys = set.map((m) => Key.fromCose(m))
    const pub = !keys.some((k) => k.hasPrivate)
    return new Identity(keys, pub ? data : null)
  }

  // COSE_Sign1 (one key) or COSE_Sign (several), kid = our address in the protected header
  sign(payload, unprotected = null) {
    if (this.signKeys.length === 1) return cose.sign1(payload, this.signKeys[0], { unprotected, kidProtected: true })
    // signers carry no kid of their own: the body kid names the identity
    return cose.sign(payload, this._sign, { protected: new Map([[cose.H_KID, this.address]]), unprotected })
  }

  // verify a Sign1/Sign made by this identity; returns the payload
  verify(signed) {
    const m = signed instanceof cose.Message ? signed : cose.decode(signed)
    if (m.kind === 'Sign1') {
      if (this.signKeys.length !== 1) throw new CoseError('identity signs with several keys but message has one signature')
      return cose.verifySign1(m, this.signKeys[0])
    }
    if (m.kind === 'Sign') return cose.verifySign(m, this.signKeys)
    throw new CoseError(`COSE_${m.kind} is not a signature`)
  }
}

// the address in the protected kid of a Sign1/Sign ("from" is in the signed header)
export function signerOf(signed) {
  const m = signed instanceof cose.Message ? signed : cose.decode(signed)
  const kid = m.protected.get(cose.H_KID)
  return isBytes(kid) && kid.length === ADDRESS_SIZE ? kid : null
}
