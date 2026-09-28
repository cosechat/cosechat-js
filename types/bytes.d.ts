export type Bytes = Uint8Array

export function toHex(b: Bytes): string
export function fromHex(s: string): Bytes
export function randomBytes(n?: number): Bytes
export function utf8(s: string): Bytes
export function fromUtf8(b: Bytes): string
export function concat(...parts: Bytes[]): Bytes
export function isBytes(b: unknown): b is Bytes
/** Constant-time comparison; false for non-bytes or different lengths. */
export function equal(a: unknown, b: unknown): boolean
export function i2osp(n: number, len: number): Bytes
export function toBase64url(b: Bytes): string
export function fromBase64url(s: string): Bytes
export function toBase32(b: Bytes): string
export function fromBase32(s: string): Bytes

/** A Map keyed by byte strings (compared by value). */
export class BytesMap<V> extends Map<any, V> {
  get(k: Bytes): V | undefined
  set(k: Bytes, v: V): this
  has(k: Bytes): boolean
  delete(k: Bytes): boolean
}
