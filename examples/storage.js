// Suggested storage for a cosechat application in Node: key files, encryption
// at rest, a ratchet rotation/retention policy, and a store-and-forward store.
// The file formats match the Python reference's examples/storage.py, so the
// two can read each other's files.
//
// The library deliberately does none of this. Where keys live, how they are
// protected, and how long they are kept depends on the device and the threat
// model. This is one reasonable choice for a desktop or server:
//
//   * Identity and ratchet files are written atomically with mode 0600.
//   * With a passphrase they are encrypted at rest: the file holds a
//     COSE_Encrypt0 (A256GCM) under a key from scrypt(passphrase, random salt).
//   * Ratchets rotate every 30 minutes and are deleted 10 days after they were
//     made, by this device's own clock (never a peer's). Deleting a ratchet is
//     what gives forward secrecy.
//   * Old key material is gone from the file, but SSDs, backups and swap may
//     keep copies: use full-disk encryption too.

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { randomBytes, scryptSync } from 'node:crypto'
import { Identity, Key } from '../src/index.js'
import { decode, encode } from '../src/cbor.js'
import * as cose from '../src/cose.js'
import { A256GCM } from '../src/keys.js'
import { newRatchet } from '../src/ratchet.js'
import { toHex } from '../src/bytes.js'

export const HOME = process.env.COSECHAT_HOME || join(homedir(), '.cosechat')
export const ROTATE_EVERY = 30 * 60
export const KEEP_FOR = 10 * 86400

const LOCKED = 'cosechat-locked-v1'
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }

function keyFrom(passphrase, salt) {
  return new Key(A256GCM, new Uint8Array(), new Uint8Array(scryptSync(passphrase, salt, 32, SCRYPT)))
}

// the locked form: CBOR [LOCKED, salt, COSE_Encrypt0]
export function lock(data, passphrase) {
  const salt = new Uint8Array(randomBytes(16))
  return encode([LOCKED, salt, cose.encrypt0(data, keyFrom(passphrase, salt))])
}

export function unlock(raw, passphrase) {
  let obj = null
  try {
    obj = decode(raw)
  } catch {}
  if (!(Array.isArray(obj) && obj.length === 3 && obj[0] === LOCKED)) return raw
  if (!passphrase) throw new Error('encrypted; a passphrase is needed')
  try {
    return cose.decrypt0(obj[2], keyFrom(passphrase, obj[1]))
  } catch {
    throw new Error('wrong passphrase')
  }
}

// atomic write, mode 0600, optionally encrypted with a passphrase
export function writePrivate(path, data, passphrase = null) {
  if (passphrase) data = lock(data, passphrase)
  mkdirSync(dirname(path), { recursive: true })
  const tmp = path + '.tmp'
  const fd = openSync(tmp, 'w', 0o600)
  try {
    writeSync(fd, data)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  renameSync(tmp, path)
}

export function readPrivate(path, passphrase = null) {
  try {
    return unlock(new Uint8Array(readFileSync(path)), passphrase)
  } catch (e) {
    throw new Error(`${path}: ${e.message}`)
  }
}

export function loadIdentity(path, { suite = 'pq', passphrase = null, create = true } = {}) {
  if (existsSync(path)) return Identity.fromBytes(readPrivate(path, passphrase))
  if (!create) throw new Error(`${path} does not exist`)
  const ident = Identity.generate(suite)
  writePrivate(path, ident.toBytes(true), passphrase)
  return ident
}

// A ratchet provider backed by a file, with a time-based policy run by
// maintain() (call it before announcing). Only the local clock is used.
export class FileRatchets {
  constructor(alg, path, { rotateEvery = ROTATE_EVERY, keepFor = KEEP_FOR, passphrase = null, clock = () => Date.now() / 1000 } = {}) {
    this.alg = alg
    this.path = path
    this.rotateEvery = rotateEvery
    this.keepFor = keepFor
    this.passphrase = passphrase
    this.clock = clock
    this._items = [] // [made at (s), key], newest first
    if (existsSync(path)) {
      for (const [made, m] of decode(readPrivate(path, passphrase))) {
        const k = Key.fromCose(m)
        if (k.alg === alg) this._items.push([made, k])
      }
      this._items.sort((a, b) => b[0] - a[0])
    }
  }

  get size() {
    return this._items.length
  }

  // ratchet provider interface
  current() {
    if (!this._items.length) this.rotate()
    return this._items[0][1]
  }

  get(rid) {
    const hex = toHex(rid)
    return this._items.find(([, k]) => toHex(k.kid) === hex)?.[1] || null
  }

  keys() {
    return this._items.map(([, k]) => k)
  }

  // policy
  rotate() {
    this._items.unshift([this.clock(), newRatchet(this.alg)])
    this._save()
    return this._items[0][1]
  }

  // delete expired ratchets and rotate if due; true if a new ratchet was made
  maintain() {
    const now = this.clock()
    const kept = this._items.filter(([t]) => now - t < this.keepFor)
    const changed = kept.length !== this._items.length
    this._items = kept
    const rotated = !this._items.length || now - this._items[0][0] >= this.rotateEvery
    if (rotated) this.rotate()
    else if (changed) this._save()
    return rotated
  }

  _save() {
    writePrivate(this.path, encode(this._items.map(([t, k]) => [t, k.toCose(true)])), this.passphrase)
  }
}

// ratchets live next to their identity: <identity>.ratchets
export function ratchetsFor(identityPath, identity, opts = {}) {
  return new FileRatchets(identity.kemAlg, identityPath + '.ratchets', opts)
}

// Apply the ratchet policy and announce, now and then every `interval`
// seconds. Returns a function that stops it.
export function announceForever(node, interval, ratchets = null) {
  let timer = null
  const tick = async () => {
    if (ratchets) ratchets.maintain()
    await node.announce()
    timer = setTimeout(tick, interval * 1000)
  }
  tick()
  return () => clearTimeout(timer)
}

// Store-and-forward held in files, for propagation nodes (see src/store.js).
// One directory per destination, one file per held packet; only ciphertext
// is ever written. Policy: at most perDest per destination, and anything
// older than keepFor (this device's clock) is deleted by maintain().
export class FileStore {
  constructor(path, { perDest = 256, keepFor = 7 * 86400, clock = () => Date.now() / 1000 } = {}) {
    this.path = path
    this.perDest = perDest
    this.keepFor = keepFor
    this.clock = clock
    mkdirSync(path, { recursive: true })
  }

  _dir(dest) {
    return join(this.path, toHex(dest))
  }

  has(dest) {
    const d = this._dir(dest)
    return existsSync(d) && readdirSync(d).length > 0
  }

  put(dest, kind, payload) {
    const d = this._dir(dest)
    mkdirSync(d, { recursive: true })
    if (readdirSync(d).length >= this.perDest) return false
    const name = `${String(Math.floor(this.clock() * 1000)).padStart(15, '0')}-${randomBytes(4).toString('hex')}`
    writePrivate(join(d, name), encode([kind, payload]))
    return true
  }

  take(dest) {
    const d = this._dir(dest)
    if (!existsSync(d)) return []
    const out = []
    for (const f of readdirSync(d).sort()) {
      if (f.endsWith('.tmp')) continue
      out.push(decode(new Uint8Array(readFileSync(join(d, f)))))
      unlinkSync(join(d, f))
    }
    return out
  }

  maintain() {
    const cutoff = (this.clock() - this.keepFor) * 1000
    for (const d of readdirSync(this.path)) {
      for (const f of readdirSync(join(this.path, d))) {
        if (Number(f.split('-')[0]) < cutoff) unlinkSync(join(this.path, d, f))
      }
    }
  }
}
