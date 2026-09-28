import type { Bytes } from './bytes.js'

export { Tagged } from 'cborg'

/** Deterministic CBOR (cbor2 canonical order). Always a fresh, plain Uint8Array. */
export function encode(value: unknown): Bytes
/** Maps decode to JS Maps; COSE tags 16/17/18/96/97/98 to Tagged. */
export function decode(data: Bytes): any
