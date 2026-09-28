// Resources: large transfers over a link (like Reticulum's Resources).
//
// The receiver pulls parts in windows, so it controls the pace and asks
// again for anything missing. Everything travels as link messages. Link body fields:
//   8   advertise  {1: resource id (16), 2: size, 3: part count, 4: SHA-256 of all, 5: meta}
//   9   request    [resource id, [part index, ...]]
//   10  part       [resource id, index, bytes]
//   11  done       resource id
// resource id = SHA-256(data)[0:16]

import { sha256 } from '@noble/hashes/sha2.js'
import { concat, equal, isBytes } from './bytes.js'
import { encode as cborEncode } from './cbor.js'
import { CoseError } from './keys.js'

export const R_ADVERTISE = 8
export const R_REQUEST = 9
export const R_PART = 10
export const R_DONE = 11

export const RESOURCE_ID_SIZE = 16
export const PART_SIZE = 320 // a part link message fits a 508-byte LoRa frame
export const WINDOW = 8 // parts asked for at a time
export const MAX_RESOURCE = 16 << 20 // receivers refuse anything bigger

export class Resource {
  constructor(peer, id, data, meta = null) {
    this.peer = peer
    this.id = id
    this.data = data
    this.meta = meta
  }
}

// sender side: the data, split, until the receiver says done
export class Outgoing {
  constructor(id, peer, parts, digest, meta, size) {
    this.id = id
    this.peer = peer
    this.parts = parts
    this.digest = digest
    this.meta = meta
    this.size = size
    this.active = -Infinity // when we last heard the receiver (node clock)
  }

  static of(peer, data, meta = null, partSize = PART_SIZE) {
    const parts = []
    for (let i = 0; i < data.length; i += partSize) parts.push(data.slice(i, i + partSize))
    if (!parts.length) parts.push(new Uint8Array())
    const digest = sha256(data)
    return new Outgoing(digest.slice(0, RESOURCE_ID_SIZE), peer, parts, digest, meta, data.length)
  }

  advertisement() {
    const ad = new Map([
      [1, this.id],
      [2, this.size],
      [3, this.parts.length],
      [4, this.digest]
    ])
    if (this.meta != null) ad.set(5, this.meta)
    return ad
  }
}

const isInt = (n) => typeof n === 'number' && Number.isInteger(n)

// receiver side: parts collected so far
export class Incoming {
  constructor(id, peer, size, count, digest, meta) {
    this.id = id
    this.peer = peer
    this.size = size
    this.count = count
    this.digest = digest
    this.meta = meta
    this.parts = new Map()
  }

  static fromAdvertisement(peer, ad, maxSize = MAX_RESOURCE) {
    if (!(ad instanceof Map)) throw new CoseError('bad resource advertisement')
    const [rid, size, count, digest] = [1, 2, 3, 4].map((k) => ad.get(k))
    if (!(isBytes(rid) && rid.length === RESOURCE_ID_SIZE && isInt(size) && isInt(count) && isBytes(digest) && digest.length === 32 && equal(digest.slice(0, RESOURCE_ID_SIZE), rid))) throw new CoseError('bad resource advertisement')
    if (size > maxSize || count < 1 || count > size + 1) throw new CoseError(`resource of ${size} bytes refused`)
    return new Incoming(rid, peer, size, count, digest, ad.get(5) ?? null)
  }

  add(index, data) {
    if (isInt(index) && index >= 0 && index < this.count && isBytes(data) && !this.parts.has(index)) this.parts.set(index, data)
  }

  missing(limit = WINDOW) {
    const out = []
    for (let i = 0; i < this.count && out.length < limit; i++) if (!this.parts.has(i)) out.push(i)
    return out
  }

  get complete() {
    return this.parts.size === this.count
  }

  assemble() {
    const parts = []
    for (let i = 0; i < this.count; i++) parts.push(this.parts.get(i))
    const data = concat(...parts)
    if (data.length !== this.size || !equal(sha256(data), this.digest)) throw new CoseError('resource does not match its hash')
    return data
  }
}

export function body(fieldId, value) {
  return new Map([[fieldId, value]])
}

export function encode(fieldId, value) {
  return cborEncode(body(fieldId, value))
}
