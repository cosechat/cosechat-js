// Ratchets: the KEM keys messages are sealed to (like Reticulum's ratchets).
//
// This module is mechanism only. When to rotate and how long to keep old
// ratchets is a storage policy for the application; the library never
// expires keys by time and never trusts dates from peers.
//
// A ratchet provider is anything with:
//   current() -> Key         the ratchet to announce (with private key)
//   get(rid) -> Key | null   the private ratchet with this id, if still held
//   keys() -> Key[]          held ratchets, newest first

import { sha256 } from '@noble/hashes/sha2.js'
import { equal } from './bytes.js'
import { CoseError, HpkeAlg, Key } from './keys.js'

export const RATCHET_ID_SIZE = 8

export function ratchetId(pub) {
  return sha256(pub).slice(0, RATCHET_ID_SIZE)
}

// a fresh ratchet using KEM `alg` (e.g. identity.kemAlg); kid = ratchet id
export function newRatchet(alg) {
  const k = Key.generate(alg)
  k.kid = ratchetId(k.pub)
  return k
}

// a ratchet must be an HPKE key carrying its own id as kid
export function checkRatchet(ratchet) {
  if (!(ratchet.algorithm instanceof HpkeAlg)) throw new CoseError('ratchet is not an HPKE key')
  if (!equal(ratchet.kid, ratchetId(ratchet.pub))) throw new CoseError('ratchet kid does not match its key')
}

// ratchets held in memory only; nothing happens on a timer
export class MemoryRatchets {
  constructor(alg, keys = [], keep = null) {
    this.alg = alg
    this.keep = keep // optional cap on how many old ratchets to hold
    this._keys = [...keys]
  }

  get size() {
    return this._keys.length
  }

  current() {
    if (!this._keys.length) this.rotate()
    return this._keys[0]
  }

  rotate() {
    this._keys.unshift(newRatchet(this.alg))
    if (this.keep != null) this._keys.length = Math.min(this._keys.length, this.keep)
    return this._keys[0]
  }

  discard(rid) {
    this._keys = this._keys.filter((k) => !equal(k.kid, rid))
  }

  get(rid) {
    return this._keys.find((k) => equal(k.kid, rid)) || null
  }

  keys() {
    return [...this._keys]
  }
}

// a provider from a provider, a plain array of keys, or nothing
export function asProvider(ratchets) {
  if (ratchets && typeof ratchets.get === 'function' && typeof ratchets.keys === 'function') return ratchets
  const held = [...(ratchets || [])]
  return { get: (rid) => held.find((k) => equal(k.kid, rid)) || null, keys: () => held }
}
