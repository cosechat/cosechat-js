import { Road } from './road.js'

export const COMPANY_ID: 0xffff
export const ADV_MAX: 251
export const BLE_MTU: 247

/** Wrap a road frame in a Manufacturer-Specific AD structure (what goes on air). */
export function encode(frame: Uint8Array): Uint8Array
/** Extract a road frame from a Manufacturer-Specific AD, or null. */
export function decode(ad: Uint8Array): Uint8Array | null

export interface BlueZOptions {
  /** BlueZ adapter: `hci1` or `/org/bluez/hci1` */
  adapter?: string | null
  secondary?: string | null
  txPower?: number | null
  /** the `dbus-next` module, injectable for tests */
  dbus?: unknown
}

/** BlueZ over D-Bus: advertise one frame at a time, and scan for frames. Linux only. */
export class BlueZ {
  constructor(opts?: BlueZOptions)
  /** true on Linux, where this transport exists */
  static readonly available: boolean
  adapter: string | null
  secondary: string | null
  maxAdvLen: number | null
  open(): Promise<void>
  advertise(frame: Uint8Array, seconds: number): Promise<void>
  scan(onFrame: (frame: Uint8Array) => void): Promise<() => Promise<void>>
  stopScan(): Promise<void>
  close(): Promise<void>
}

export interface BLERoadOptions extends BlueZOptions {
  /** how long each frame stays on air (ms) */
  advMs?: number
  name?: string | null
}

/** Anonymous BLE extended-advertising road. Needs Linux + BlueZ + dbus-next. */
export class BLERoad extends Road {
  constructor(opts?: BLERoadOptions)
  readonly adapter: string | null
  advMs: number
  txReady: boolean
  bluez: BlueZ
}
