import type { Bytes } from './bytes.js'
import type { Key } from './keys.js'

export const RATCHET_ID_SIZE: 8
export function ratchetId(pub: Bytes): Bytes
export function newRatchet(alg: number): Key
export function checkRatchet(ratchet: Key): void

/** Where a node's ratchets live; rotation and retention are the application's policy. */
export interface RatchetProvider {
  /** the ratchet to announce (with its private key) */
  current(): Key
  /** the private ratchet with this id, if still held */
  get(rid: Bytes): Key | null
  /** held ratchets, newest first */
  keys(): Key[]
  rotate?(): Key
}

export class MemoryRatchets implements RatchetProvider {
  constructor(alg: number, keys?: Key[], keep?: number | null)
  alg: number
  keep: number | null
  readonly size: number
  current(): Key
  rotate(): Key
  discard(rid: Bytes): void
  get(rid: Bytes): Key | null
  keys(): Key[]
}

export function asProvider(ratchets: RatchetProvider | Iterable<Key> | null | undefined): Pick<RatchetProvider, 'get' | 'keys'>
