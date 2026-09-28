import type { Bytes } from './bytes.js'

/** Store-and-forward storage for propagation nodes (only ever holds ciphertext). */
export interface Store {
  put(dest: Bytes, kind: number, payload: Bytes): boolean | Promise<boolean>
  take(dest: Bytes): [number, Bytes][] | Promise<[number, Bytes][]>
}

export class MemoryStore implements Store {
  constructor(opts?: { perDest?: number; maxDests?: number })
  has(dest: Bytes): boolean
  put(dest: Bytes, kind: number, payload: Bytes): boolean
  take(dest: Bytes): [number, Bytes][]
}
