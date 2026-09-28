// CBOR helpers. Maps are sorted like cbor2's canonical mode (RFC 7049 3.9:
// shorter encoded key first, then bytewise), so JS and Python emit identical
// bytes. Decoded maps are always JS Maps (COSE uses integer keys).

import { Tagged, Token, decode as cborgDecode, encode as cborgEncode } from 'cborg'

export { Tagged }

const TAGS = [16, 17, 18, 96, 97, 98]

function keyBytes(t) {
  if (!t._kb) t._kb = cborgEncode(t.value)
  return t._kb
}

function mapSorter(e1, e2) {
  if (!(e1[0] instanceof Token) || !(e2[0] instanceof Token)) throw new Error('complex CBOR map keys are not supported')
  const a = keyBytes(e1[0])
  const b = keyBytes(e2[0])
  if (a.length !== b.length) return a.length - b.length
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]
  return 0
}

const encodeOptions = { mapSorter }

const tags = []
for (const t of TAGS) tags[t] = Tagged.decoder(t)
const decodeOptions = { useMaps: true, tags, rejectDuplicateMapKeys: true }

export function encode(value) {
  return cborgEncode(value, encodeOptions)
}

export function decode(data) {
  return cborgDecode(data, decodeOptions)
}

// read a map field that may be a Map (decoded) or a plain object (user input)
export function get(m, k) {
  if (m instanceof Map) return m.get(k)
  if (m && typeof m === 'object') return m[k]
  return undefined
}
