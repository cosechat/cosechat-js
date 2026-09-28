import type { Bytes } from './bytes.js'
import type { Key } from './keys.js'
import type { Message } from './cose.js'

export type SuiteName = 'pq' | 'hybrid' | 'prequantum'

export const ADDRESS_SIZE: 16
/** name -> [signing algs, KEM alg for its ratchets] */
export const SUITES: Record<SuiteName, [number[], number]>
export function addressOf(publicBytes: Bytes): Bytes

/** A COSE_KeySet of signing keys; its address is SHA-256(public keyset)[0:16]. */
export class Identity {
  constructor(signKeys: Key[], publicBytes?: Bytes | null)
  readonly publicBytes: Bytes
  readonly address: Bytes
  readonly signKeys: Key[]
  readonly quantumSafe: boolean
  /** HPKE-9 (X-Wing) for quantum-safe identities, else HPKE-0 */
  readonly kemAlg: number
  readonly hasPrivate: boolean
  static generate(suite?: SuiteName): Identity
  static fromBytes(data: Bytes): Identity
  equals(other: unknown): boolean
  public(): Identity
  /** COSE_KeySet; with priv (the default) it holds secrets. */
  toBytes(priv?: boolean): Bytes
  sign(payload: Bytes, unprotected?: Map<number, unknown> | null): Bytes
  verify(signed: Bytes | Message): Bytes
}

/** The address in the protected kid of a Sign1/Sign, or null. */
export function signerOf(signed: Bytes | Message): Bytes | null
