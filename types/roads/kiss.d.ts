import type { Bytes } from '../bytes.js'

export const FEND: 0xc0
export const FESC: 0xdb
export const TFEND: 0xdc
export const TFESC: 0xdd
export function escape(data: Bytes): Bytes
export function unescape(data: Bytes): Bytes
export function frame(cmd: number, data?: Bytes): Bytes
export class Decoder {
  constructor(maxSize?: number)
  /** complete [cmd, data] frames */
  feed(data: Bytes): [number, Bytes][]
}
