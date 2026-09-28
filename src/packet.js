// Packets: what travels on a road.
//
//   packet   = [version, type, hops, dest, via, payload]
//   fragment = [version, 3, id, index, count, chunk]
//   nack     = [version, 10, id, [missing indexes]]
//   road frame = packet | fragment, optionally wrapped in COSE_Mac0 or
//                COSE_Encrypt0 under a road key (RoadAuth)
//
// The packet hash (duplicate suppression) covers only the immutable parts:
// SHA-256(CBOR [version, type, dest, payload]).

import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { concat, isBytes, randomBytes, toHex, utf8 } from './bytes.js'
import { decode as cborDecode, encode } from './cbor.js'
import * as cose from './cose.js'
import { ADDRESS_SIZE } from './identity.js'
import { A256GCM, HMAC_256_256, Key, getAlg } from './keys.js'

export const VERSION = 0

export const ANNOUNCE = 0
export const DATA = 1
export const PATH_REQUEST = 2
export const FRAGMENT = 3
export const RECEIPT = 4
export const LINK_REQUEST = 5
export const LINK_ACCEPT = 6
export const LINK_DATA = 7
export const KEYSET_REQUEST = 8
export const KEYSET = 9
export const FRAGMENT_NACK = 10

export const TYPES = {
  [ANNOUNCE]: 'ANNOUNCE',
  [DATA]: 'DATA',
  [PATH_REQUEST]: 'PATH_REQUEST',
  [RECEIPT]: 'RECEIPT',
  [LINK_REQUEST]: 'LINK_REQUEST',
  [LINK_ACCEPT]: 'LINK_ACCEPT',
  [LINK_DATA]: 'LINK_DATA',
  [KEYSET_REQUEST]: 'KEYSET_REQUEST',
  [KEYSET]: 'KEYSET'
}
// addressed to a node and routed like DATA
export const ROUTED = new Set([DATA, RECEIPT, LINK_REQUEST, LINK_ACCEPT, LINK_DATA])

export const FRAGMENT_ID_SIZE = 8
export const REQUEST_TAG_SIZE = 8 // random tag in path and keyset requests
export const RECEIPT_NONCE_SIZE = 8 // random bytes after a receipt tag
export const NACK_MAX_INDEXES = 4096
export const REASSEMBLY_TIMEOUT = 60 // incomplete fragment sets are dropped after this (s)
export const REASSEMBLY_SETS = 256
export const REASSEMBLY_MAX_BYTES = 1 << 20
export const REASSEMBLY_DONE_CACHE = 1024 // completed sets remembered, to ignore late resends
// array(1) + version(1) + type(1) + id(1+8) + index(3) + count(3) + chunk header(3)
export const FRAGMENT_OVERHEAD = 21

export class PacketError extends Error {
  constructor(message) {
    super(message)
    this.name = 'PacketError'
  }
}

export class Packet {
  constructor(type, hops, dest, via, payload) {
    this.type = type
    this.hops = hops
    this.dest = dest
    this.via = via
    this.payload = payload
  }

  encode() {
    return encode([VERSION, this.type, this.hops, this.dest, this.via, this.payload])
  }

  get hash() {
    return sha256(encode([VERSION, this.type, this.dest, this.payload]))
  }

  toString() {
    const via = this.via ? toHex(this.via).slice(0, 8) : '-'
    return `<${TYPES[this.type] ?? this.type} dest=${toHex(this.dest).slice(0, 8)} hops=${this.hops} via=${via} ${this.payload.length}B>`
  }
}

export class Fragment {
  constructor(fid, index, count, chunk) {
    this.fid = fid
    this.index = index
    this.count = count
    this.chunk = chunk
  }
}

export class Nack {
  constructor(fid, missing) {
    this.fid = fid
    this.missing = missing
  }
}

const isInt = (n) => typeof n === 'number' && Number.isInteger(n)
const isAddr = (a) => isBytes(a) && a.length === ADDRESS_SIZE

// a Packet, a Fragment or a Nack; throws PacketError for anything else
export function decode(frame) {
  let arr
  try {
    arr = cborDecode(frame)
  } catch (e) {
    throw new PacketError(`bad CBOR: ${e.message}`)
  }
  if (!Array.isArray(arr) || arr.length < 2 || !isInt(arr[0]) || !isInt(arr[1])) throw new PacketError('not a packet')
  if (arr[0] !== VERSION) throw new PacketError(`unsupported protocol version ${arr[0]}`)
  const t = arr[1]
  if (t === FRAGMENT) {
    const [, , fid, index, count, chunk] = arr
    if (arr.length !== 6 || !isBytes(fid) || !isBytes(chunk) || !isInt(index) || !isInt(count) || index < 0 || index >= count) throw new PacketError('bad fragment')
    return new Fragment(fid, index, count, chunk)
  }
  if (t === FRAGMENT_NACK) {
    const [, , fid, missing] = arr
    if (arr.length !== 4 || !isBytes(fid) || !Array.isArray(missing)) throw new PacketError('bad nack')
    if (missing.length > NACK_MAX_INDEXES || !missing.every((i) => isInt(i) && i >= 0)) throw new PacketError('bad nack')
    return new Nack(fid, missing)
  }
  if (!(t in TYPES) || arr.length !== 6) throw new PacketError('unknown packet type')
  const [, , hops, dest, via, payload] = arr
  if (!isAddr(dest) || !(via === null || isAddr(via))) throw new PacketError('bad address')
  if (!isInt(hops) || hops < 0 || !isBytes(payload)) throw new PacketError('bad packet')
  return new Packet(t, hops, dest, via, payload)
}

export function nack(fid, missing) {
  return encode([VERSION, FRAGMENT_NACK, fid, missing])
}

export function fragment(frame, chunkSize, fid = null) {
  if (chunkSize <= 0) throw new PacketError('road MTU too small to fragment into')
  fid = fid || randomBytes(FRAGMENT_ID_SIZE)
  const chunks = []
  for (let i = 0; i < frame.length; i += chunkSize) chunks.push(frame.slice(i, i + chunkSize))
  return chunks.map((c, i) => encode([VERSION, FRAGMENT, fid, i, chunks.length, c]))
}

const monotonic = () => performance.now() / 1000

// collects fragments per (source key, fragment id); incomplete sets expire
export class Reassembler {
  constructor({ timeout = REASSEMBLY_TIMEOUT, maxSets = REASSEMBLY_SETS, maxSize = REASSEMBLY_MAX_BYTES, clock = monotonic } = {}) {
    this.timeout = timeout
    this.maxSets = maxSets
    this.maxSize = maxSize
    this.clock = clock
    this._sets = new Map()
    this._done = new Map() // recently completed, to ignore late resends
  }

  static key(source, fid) {
    return `${source}/${toHex(fid)}`
  }

  // indexes still missing from an incomplete set, or null if there is no such set
  missing(source, fid) {
    const e = this._sets.get(Reassembler.key(source, fid))
    if (!e) return null
    const out = []
    for (let i = 0; i < e.count; i++) if (!e.chunks.has(i)) out.push(i)
    return out
  }

  add(source, frag) {
    const now = this.clock()
    this._expire(now)
    const key = Reassembler.key(source, frag.fid)
    if (this._done.has(key)) return null
    let e = this._sets.get(key)
    if (!e) {
      if (this._sets.size >= this.maxSets) this._sets.delete(this._sets.keys().next().value)
      e = { count: frag.count, chunks: new Map(), size: 0, time: now }
      this._sets.set(key, e)
    }
    if (e.count !== frag.count) {
      this._sets.delete(key)
      return null
    }
    if (!e.chunks.has(frag.index)) {
      e.chunks.set(frag.index, frag.chunk)
      e.size += frag.chunk.length
    }
    if (e.size > this.maxSize) {
      this._sets.delete(key)
      return null
    }
    if (e.chunks.size === e.count) {
      this._sets.delete(key)
      this._done.set(key, true)
      if (this._done.size > REASSEMBLY_DONE_CACHE) this._done.delete(this._done.keys().next().value)
      const parts = []
      for (let i = 0; i < e.count; i++) parts.push(e.chunks.get(i))
      return concat(...parts)
    }
    return null
  }

  _expire(now) {
    for (const [k, e] of this._sets) if (now - e.time > this.timeout) this._sets.delete(k)
  }
}

// Optional per-road protection with a shared road key (like Reticulum IFAC):
//   mode 'mac'      frames are COSE_Mac0 (outsiders can read headers, cannot inject)
//   mode 'encrypt'  frames are COSE_Encrypt0 (outsiders cannot even see addresses)
export class RoadAuth {
  constructor(key, mode = 'mac') {
    if (mode !== 'mac' && mode !== 'encrypt') throw new Error('mode must be mac or encrypt')
    this.key = key
    this.mode = mode
    this.overhead = this.wrap(new Uint8Array()).length + 3
  }

  static fromPassphrase(passphrase, mode = 'mac') {
    const alg = mode === 'mac' ? HMAC_256_256 : A256GCM
    const k = hkdf(sha256, utf8(passphrase), utf8('cosechat road key'), utf8(mode), getAlg(alg).keySize)
    return new RoadAuth(new Key(alg, new Uint8Array(), k), mode)
  }

  wrap(frame) {
    return this.mode === 'mac' ? cose.mac0(frame, this.key) : cose.encrypt0(frame, this.key)
  }

  unwrap(data) {
    try {
      return this.mode === 'mac' ? cose.verifyMac0(data, this.key) : cose.decrypt0(data, this.key)
    } catch (e) {
      throw new PacketError(`road auth failed: ${e.message}`)
    }
  }
}
