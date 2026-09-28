// CBOR helpers. Maps are sorted like cbor2's canonical mode (RFC 7049 3.9:
// shorter encoded key first, then bytewise), so JS and Python emit identical
// bytes. Decoded maps are always JS Maps (COSE uses integer keys).

import { Tagged, Token, decode as cborgDecode, encode as cborgEncode } from 'cborg'

export { Tagged }

const TAGS = [16, 17, 18, 96, 97, 98]
const te = new TextEncoder()

// CBOR head for a map key. Written out here because cborg's encoder is not
// reentrant (it shares one output buffer), so it cannot run inside a sorter.
function head(major, n) {
  if (n < 24n) return [(major << 5) | Number(n)]
  const size = n < 0x100n ? 1 : n < 0x10000n ? 2 : n < 0x100000000n ? 4 : 8
  const out = [(major << 5) | { 1: 24, 2: 25, 4: 26, 8: 27 }[size]]
  const b = []
  for (let i = 0; i < size; i++) {
    b.unshift(Number(n & 0xffn))
    n >>= 8n
  }
  return out.concat(b)
}

function keyBytes(t) {
  if (t._kb) return t._kb
  const v = t.value
  let kb
  if (typeof v === 'number' || typeof v === 'bigint') {
    if (typeof v === 'number' && !Number.isInteger(v)) throw new Error('float CBOR map keys are not supported')
    const n = BigInt(v)
    kb = n >= 0n ? head(0, n) : head(1, -1n - n)
  } else if (typeof v === 'string') {
    const b = te.encode(v)
    kb = head(3, BigInt(b.length)).concat(Array.from(b))
  } else if (v instanceof Uint8Array) {
    kb = head(2, BigInt(v.length)).concat(Array.from(v))
  } else {
    throw new Error('unsupported CBOR map key type')
  }
  t._kb = kb
  return kb
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

// Always a fresh, plain Uint8Array. In Node, cborg sometimes hands back a
// Buffer from the shared allocation pool, and Buffer#slice is a view, not a
// copy: code that copies with slice() would then change the original.
export function encode(value) {
  const out = cborgEncode(value, encodeOptions)
  return Object.getPrototypeOf(out) === Uint8Array.prototype ? out : new Uint8Array(out)
}

export function decode(data) {
  return cborgDecode(data, decodeOptions)
}
