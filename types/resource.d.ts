import type { Bytes } from './bytes.js'

export const R_ADVERTISE: 8
export const R_REQUEST: 9
export const R_PART: 10
export const R_DONE: 11
export const RESOURCE_ID_SIZE: 16
export const PART_SIZE: 320
export const WINDOW: 8
export const MAX_RESOURCE: number

/** What onResource hands you: a large transfer that arrived whole. */
export class Resource {
  constructor(peer: Bytes, id: Bytes, data: Bytes, meta?: unknown)
  peer: Bytes
  id: Bytes
  data: Bytes
  meta: any
}

export class Outgoing {
  id: Bytes
  peer: Bytes
  parts: Bytes[]
  digest: Bytes
  meta: unknown
  size: number
  active: number
  static of(peer: Bytes, data: Bytes, meta?: unknown, partSize?: number): Outgoing
  advertisement(): Map<number, unknown>
}

export class Incoming {
  id: Bytes
  peer: Bytes
  size: number
  count: number
  digest: Bytes
  meta: unknown
  parts: Map<number, Bytes>
  readonly complete: boolean
  static fromAdvertisement(peer: Bytes, ad: Map<number, unknown>, maxSize?: number): Incoming
  add(index: number, data: Bytes): void
  missing(limit?: number): number[]
  assemble(): Bytes
}

export function body(fieldId: number, value: unknown): Map<number, unknown>
export function encode(fieldId: number, value: unknown): Bytes
