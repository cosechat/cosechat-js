import { Road, type RoadOptions } from './road.js'

export const WIFI_MTU: 252

/** Wrap payload in an 802.11 vendor-specific action frame. */
export function encode(payload: Uint8Array, src?: Uint8Array | null): Uint8Array
/** Extract payload from an 802.11 action frame, or null. */
export function decode(frame: Uint8Array): Uint8Array | null

export class RawWifiRoad extends Road {
  constructor(opts?: { interface?: string | null; channel?: number; name?: string | null })
  interface: string | null
  channel: number
  src: Uint8Array
}
