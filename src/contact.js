// Sharing contacts.
//
// Address text: the 16-byte address in base32 (RFC 4648, lowercase, no
// padding) plus a 4-character checksum, in groups of 5:
//   addressText(a) -> 'mfrgg-zdfmz-tsnjx-gc3dm-nzsgm-3j5hu'
// A contact card is a full announce: cardUri(announce) -> 'cosechat:' + base64url(announce)

import { sha256 } from '@noble/hashes/sha2.js'
import { concat, fromBase32, fromBase64url, fromHex, toBase32, toBase64url, utf8 } from './bytes.js'
import { ADDRESS_SIZE } from './identity.js'
import { CoseError } from './keys.js'

export const URI_PREFIX = 'cosechat:'
export const CHECK_SIZE = 4 // base32 characters of checksum (20 bits)

function check(address) {
  return toBase32(sha256(concat(utf8('cosechat address'), address))).slice(0, CHECK_SIZE)
}

export function addressText(address) {
  if (address.length !== ADDRESS_SIZE) throw new Error('an address is 16 bytes')
  const s = toBase32(address) + check(address)
  return s.match(/.{1,5}/g).join('-')
}

// address text (checksum verified) or plain hex, to the 16-byte address
export function parseAddress(text) {
  const t = text.trim().toLowerCase().replace(/[-\s]/g, '')
  if (t.length === ADDRESS_SIZE * 2 && /^[0-9a-f]+$/.test(t)) return fromHex(t)
  if (t.length !== 26 + CHECK_SIZE) throw new CoseError('not an address')
  let address
  try {
    address = fromBase32(t.slice(0, 26))
  } catch {
    throw new CoseError('not an address')
  }
  if (address.length !== ADDRESS_SIZE || check(address) !== t.slice(26)) throw new CoseError('address checksum does not match (typo?)')
  return address
}

export function cardUri(announce) {
  return URI_PREFIX + toBase64url(announce)
}

export function cardFromUri(uri) {
  const u = uri.trim()
  if (!u.startsWith(URI_PREFIX)) throw new CoseError('not a cosechat contact card')
  try {
    return fromBase64url(u.slice(URI_PREFIX.length))
  } catch {
    throw new CoseError('bad contact card')
  }
}
