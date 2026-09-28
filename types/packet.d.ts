import type { Bytes } from './bytes.js'
import type { Key } from './keys.js'

export const VERSION: 0
export const ANNOUNCE: 0
export const DATA: 1
export const PATH_REQUEST: 2
export const FRAGMENT: 3
export const RECEIPT: 4
export const LINK_REQUEST: 5
export const LINK_ACCEPT: 6
export const LINK_DATA: 7
export const KEYSET_REQUEST: 8
export const KEYSET: 9
export const FRAGMENT_NACK: 10
export const TYPES: Record<number, string>
export const ROUTED: Set<number>
export const FRAGMENT_ID_SIZE: 8
export const REQUEST_TAG_SIZE: 8
export const RECEIPT_NONCE_SIZE: 8
export const NACK_MAX_INDEXES: 4096
export const REASSEMBLY_TIMEOUT: number
export const REASSEMBLY_SETS: number
export const REASSEMBLY_MAX_BYTES: number
export const REASSEMBLY_DONE_CACHE: number
export const FRAGMENT_OVERHEAD: 21

export class PacketError extends Error {}

/** [version, type, hops, dest, via, payload] */
export class Packet {
  constructor(type: number, hops: number, dest: Bytes, via: Bytes | null, payload: Bytes)
  type: number
  hops: number
  dest: Bytes
  via: Bytes | null
  payload: Bytes
  encode(): Bytes
  /** SHA-256(CBOR [version, type, dest, payload]) */
  readonly hash: Bytes
}
export class Fragment {
  constructor(fid: Bytes, index: number, count: number, chunk: Bytes)
  fid: Bytes
  index: number
  count: number
  chunk: Bytes
}
export class Nack {
  constructor(fid: Bytes, missing: number[])
  fid: Bytes
  missing: number[]
}

export function decode(frame: Bytes): Packet | Fragment | Nack
export function nack(fid: Bytes, missing: number[]): Bytes
export function fragment(frame: Bytes, chunkSize: number, fid?: Bytes | null): Bytes[]

export class Reassembler {
  constructor(opts?: { timeout?: number; maxSets?: number; maxSize?: number; clock?: () => number })
  missing(source: string | number, fid: Bytes): number[] | null
  add(source: string | number, frag: Fragment): Bytes | null
}

/** Per-road key (like Reticulum IFAC): 'mac' frames are COSE_Mac0, 'encrypt' COSE_Encrypt0. */
export class RoadAuth {
  constructor(key: Key, mode?: 'mac' | 'encrypt')
  key: Key
  mode: 'mac' | 'encrypt'
  overhead: number
  static fromPassphrase(passphrase: string, mode?: 'mac' | 'encrypt'): RoadAuth
  wrap(frame: Bytes): Bytes
  unwrap(data: Bytes): Bytes
}
