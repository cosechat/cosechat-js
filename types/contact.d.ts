import type { Bytes } from './bytes.js'

export const URI_PREFIX: 'cosechat:'
export const CHECK_SIZE: 4
/** base32 + 4-character checksum, in groups of 5 */
export function addressText(address: Bytes): string
/** address text (checksum verified) or hex */
export function parseAddress(text: string): Bytes
export function cardUri(announce: Bytes): string
export function cardFromUri(uri: string): Bytes
