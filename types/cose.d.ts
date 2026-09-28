import type { Bytes } from './bytes.js'
import type { Key } from './keys.js'

export const H_ALG: 1
export const H_CRIT: 2
export const H_CTY: 3
export const H_KID: 4
export const H_IV: 5
export const H_PARTIAL_IV: 6
export const H_EK: -4
export const TAG_ENCRYPT0: 16
export const TAG_MAC0: 17
export const TAG_SIGN1: 18
export const TAG_ENCRYPT: 96
export const TAG_MAC: 97
export const TAG_SIGN: 98
export const KINDS: Record<number, 'Encrypt0' | 'Mac0' | 'Sign1' | 'Encrypt' | 'Mac' | 'Sign'>

export type Headers = Map<number, unknown> | Record<number, unknown>

export class Layer {
  rawProtected: Bytes
  unprotected: Map<number, unknown>
  protected: Map<number, unknown>
  header(label: number): unknown
  readonly alg: number | undefined
  readonly kid: Bytes | undefined
}

export class Message extends Layer {
  kind: 'Encrypt0' | 'Mac0' | 'Sign1' | 'Encrypt' | 'Mac' | 'Sign'
  /** payload (sign/mac) or ciphertext (encrypt) */
  content: Bytes | null
  signature: Bytes | null
  signers: [Layer, Bytes][]
  recipients: [Layer, Bytes][]
}

type CoseInput = Bytes | Message

export interface SignOptions {
  protected?: Headers
  unprotected?: Headers
  externalAad?: Bytes
}

export function decode(data: Bytes | unknown, expect?: number | null): Message

export function sign1(payload: Bytes, key: Key, opts?: SignOptions & { kidProtected?: boolean }): Bytes
export function verifySign1(data: CoseInput, key: Key, externalAad?: Bytes): Bytes
export function sign(payload: Bytes, keys: Key[], opts?: SignOptions): Bytes
/** Every key given must have produced a valid signature. */
export function verifySign(data: CoseInput, keys: Key[], externalAad?: Bytes): Bytes
export function mac0(payload: Bytes, key: Key, opts?: SignOptions): Bytes
export function verifyMac0(data: CoseInput, key: Key, externalAad?: Bytes): Bytes
export function mac(payload: Bytes, recipients: Key[], opts?: SignOptions & { alg?: number; includeKid?: boolean }): Bytes
export function verifyMac(data: CoseInput, key: Key, externalAad?: Bytes): Bytes
/** `key` is a shared AEAD key, or the recipient's HPKE public key. `iv` only for test vectors. */
export function encrypt0(plaintext: Bytes, key: Key, opts?: SignOptions & { includeKid?: boolean; iv?: Bytes | null }): Bytes
export function decrypt0(data: CoseInput, key: Key, externalAad?: Bytes): Bytes
export function encrypt(plaintext: Bytes, recipients: Key[], opts?: SignOptions & { alg?: number; includeKid?: boolean }): Bytes
export function decrypt(data: CoseInput, key: Key, externalAad?: Bytes): Bytes
