// Byte helpers. Everything in cosechat is a Uint8Array.

import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js'

export { bytesToHex as toHex, hexToBytes as fromHex, randomBytes, utf8ToBytes as utf8 }

const td = new TextDecoder()

export function fromUtf8(b) {
  return td.decode(b)
}

export function concat(...parts) {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

export function isBytes(b) {
  return b instanceof Uint8Array
}

export function equal(a, b) {
  if (!isBytes(a) || !isBytes(b) || a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]
  return d === 0
}

export function i2osp(n, len) {
  const out = new Uint8Array(len)
  for (let i = len - 1; i >= 0; i--) {
    out[i] = n & 0xff
    n = Math.floor(n / 256)
  }
  return out
}

// a Map keyed by byte strings (by hex), for address/id tables
export class BytesMap extends Map {
  get(k) {
    return super.get(bytesToHex(k))
  }

  set(k, v) {
    return super.set(bytesToHex(k), v)
  }

  has(k) {
    return super.has(bytesToHex(k))
  }

  delete(k) {
    return super.delete(bytesToHex(k))
  }
}

// --- base64url / base32 (RFC 4648, no padding) ---

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

export function toBase64url(b) {
  let s = ''
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0)
    const k = Math.min(3, b.length - i) + 1
    for (let j = 0; j < k; j++) s += B64[(n >> (18 - 6 * j)) & 63]
  }
  return s
}

export function fromBase64url(s) {
  s = s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const out = []
  let acc = 0
  let bits = 0
  for (const c of s) {
    const v = B64.indexOf(c)
    if (v < 0) throw new Error('bad base64url')
    acc = (acc << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((acc >> bits) & 0xff)
    }
  }
  return new Uint8Array(out)
}

const B32 = 'abcdefghijklmnopqrstuvwxyz234567'

export function toBase32(b) {
  let s = ''
  let acc = 0
  let bits = 0
  for (const x of b) {
    acc = (acc << 8) | x
    bits += 8
    while (bits >= 5) {
      bits -= 5
      s += B32[(acc >> bits) & 31]
    }
    acc &= (1 << bits) - 1
  }
  if (bits > 0) s += B32[(acc << (5 - bits)) & 31]
  return s
}

export function fromBase32(s) {
  const out = []
  let acc = 0
  let bits = 0
  for (const c of s.toLowerCase()) {
    const v = B32.indexOf(c)
    if (v < 0) throw new Error('bad base32')
    acc = (acc << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((acc >> bits) & 0xff)
    }
    acc &= (1 << bits) - 1
  }
  return new Uint8Array(out)
}
