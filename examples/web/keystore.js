// Key storage for the web example: IndexedDB, optionally locked with a
// passphrase. The locked form is the one examples/storage.js (Node) and the
// Python reference's examples/storage.py write:
//
//   CBOR ["cosechat-locked-v1", salt(16), COSE_Encrypt0 (A256GCM)]
//   key = scrypt(passphrase, salt, N=2^15, r=8, p=1, 32 bytes)
//
// Like any browser storage, IndexedDB can be cleared by the user or the
// browser, and is readable by anything running on this origin.

import { scryptAsync } from '@noble/hashes/scrypt.js'
import { Key } from 'cosechat/index.js'
import { randomBytes } from 'cosechat/bytes.js'
import { decode, encode } from 'cosechat/cbor.js'
import * as cose from 'cosechat/cose.js'
import { A256GCM } from 'cosechat/keys.js'

const LOCKED = 'cosechat-locked-v1'

async function keyFrom(passphrase, salt) {
  return new Key(A256GCM, new Uint8Array(), await scryptAsync(passphrase, salt, { N: 2 ** 15, r: 8, p: 1, dkLen: 32 }))
}

export function isLocked(raw) {
  try {
    const obj = decode(raw)
    return Array.isArray(obj) && obj.length === 3 && obj[0] === LOCKED
  } catch {
    return false
  }
}

export async function lock(data, passphrase) {
  const salt = randomBytes(16)
  return encode([LOCKED, salt, cose.encrypt0(data, await keyFrom(passphrase, salt))])
}

export class WrongPassphrase extends Error {}

export async function unlock(raw, passphrase) {
  if (!isLocked(raw)) return raw
  const [, salt, sealed] = decode(raw)
  try {
    return cose.decrypt0(sealed, await keyFrom(passphrase, salt))
  } catch {
    throw new WrongPassphrase('wrong passphrase')
  }
}

export class KeyStore {
  constructor(db) {
    this.db = db
    this.passphrase = null // set once unlocked (or when locking)
  }

  static open(name = 'cosechat') {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(name, 1)
      req.onupgradeneeded = () => req.result.createObjectStore('kv')
      req.onsuccess = () => resolve(new KeyStore(req.result))
      req.onerror = () => reject(req.error)
    })
  }

  _tx(mode, fn) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction('kv', mode)
      const req = fn(tx.objectStore('kv'))
      tx.oncomplete = () => resolve(req.result)
      tx.onerror = () => reject(tx.error)
    })
  }

  get(k) {
    return this._tx('readonly', (s) => s.get(k))
  }

  set(k, v) {
    return this._tx('readwrite', (s) => s.put(v, k))
  }

  del(k) {
    return this._tx('readwrite', (s) => s.delete(k))
  }

  // bytes as stored (locked or not), or undefined
  async raw(k) {
    const v = await this.get(k)
    return v instanceof Uint8Array ? v : v ? new Uint8Array(v) : undefined
  }

  async readPrivate(k) {
    const raw = await this.raw(k)
    if (raw === undefined) return undefined
    return unlock(raw, this.passphrase)
  }

  async writePrivate(k, data) {
    await this.set(k, this.passphrase ? await lock(data, this.passphrase) : data)
  }
}
