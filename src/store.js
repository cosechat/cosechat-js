// Store-and-forward storage for propagation nodes. What it keeps is only
// ever ciphertext plus the packet type. A store provider has:
//   put(dest, kind, payload) -> boolean   keep one; false if there is no room
//   take(dest) -> [[kind, payload]]       everything held for dest, oldest first, removed
// (both may return promises). MemoryStore is bounded, and gone on restart.

import { toHex } from './bytes.js'

export class MemoryStore {
  constructor({ perDest = 64, maxDests = 1024 } = {}) {
    this.perDest = perDest
    this.maxDests = maxDests
    this._held = new Map()
  }

  has(dest) {
    return this._held.has(toHex(dest))
  }

  put(dest, kind, payload) {
    const k = toHex(dest)
    let q = this._held.get(k)
    if (!q) {
      if (this._held.size >= this.maxDests) return false
      q = []
      this._held.set(k, q)
    }
    if (q.length >= this.perDest) return false
    q.push([kind, payload])
    return true
  }

  take(dest) {
    const k = toHex(dest)
    const q = this._held.get(k) || []
    this._held.delete(k)
    return q
  }
}
