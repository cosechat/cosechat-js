// KISS framing (as used by RNode firmware): FEND cmd data FEND, with FESC escaping.

export const FEND = 0xc0
export const FESC = 0xdb
export const TFEND = 0xdc
export const TFESC = 0xdd

export function escape(data) {
  const out = []
  for (const b of data) {
    if (b === FESC) out.push(FESC, TFESC)
    else if (b === FEND) out.push(FESC, TFEND)
    else out.push(b)
  }
  return new Uint8Array(out)
}

export function unescape(data) {
  const out = []
  let esc = false
  for (const b of data) {
    if (esc) {
      out.push(b === TFEND ? FEND : b === TFESC ? FESC : b)
      esc = false
    } else if (b === FESC) esc = true
    else out.push(b)
  }
  return new Uint8Array(out)
}

export function frame(cmd, data = new Uint8Array()) {
  const body = escape(data)
  const out = new Uint8Array(body.length + 3)
  out[0] = FEND
  out[1] = cmd
  out.set(body, 2)
  out[out.length - 1] = FEND
  return out
}

// feed raw serial bytes, get back complete [cmd, data] frames
export class Decoder {
  constructor(maxSize = 4096) {
    this.maxSize = maxSize
    this._buf = []
    this._inFrame = false
  }

  feed(data) {
    const out = []
    for (const b of data) {
      if (b === FEND) {
        if (this._inFrame && this._buf.length) {
          const body = unescape(this._buf)
          out.push([body[0], body.slice(1)])
        }
        this._buf = []
        this._inFrame = true
      } else if (this._inFrame) {
        if (this._buf.length < this.maxSize) this._buf.push(b)
        else {
          this._buf = []
          this._inFrame = false
        }
      }
    }
    return out
  }
}
