import { Road } from './road.js'
import type { SerialLike } from './serial.js'

export const CMD_DATA: 0x00
export const CMD_FREQUENCY: 0x01
export const CMD_BANDWIDTH: 0x02
export const CMD_TXPOWER: 0x03
export const CMD_SF: 0x04
export const CMD_CR: 0x05
export const CMD_RADIO_STATE: 0x06
export const CMD_RADIO_LOCK: 0x07
export const CMD_DETECT: 0x08
export const CMD_LEAVE: 0x0a
export const CMD_ST_ALOCK: 0x0b
export const CMD_LT_ALOCK: 0x0c
export const CMD_READY: 0x0f
export const CMD_STAT_RX: 0x21
export const CMD_STAT_TX: 0x22
export const CMD_STAT_RSSI: 0x23
export const CMD_STAT_SNR: 0x24
export const CMD_PLATFORM: 0x48
export const CMD_MCU: 0x49
export const CMD_FW_VERSION: 0x50
export const CMD_RESET: 0x55
export const CMD_ERROR: 0x90
export const DETECT_REQ: 0x73
export const DETECT_RESP: 0x46
export const RADIO_STATE_OFF: 0x00
export const RADIO_STATE_ON: 0x01
export const ERRORS: Record<number, string>
export const RSSI_OFFSET: 157
export const REQUIRED_FIRMWARE: [number, number]
export const HW_MTU: 508

export class RNodeError extends Error {}

export interface RNodeOptions {
  /** Hz: use one your region allows */
  frequency: number
  bandwidth?: number
  txpower?: number
  sf?: number
  cr?: number
  stAlock?: number | null
  ltAlock?: number | null
  flowControl?: boolean
  baudRate?: number
  /** seconds to wait after opening the port */
  bootDelay?: number
  timeout?: number
  name?: string | null
}

/** LoRa through an RNode. `port`: a device path (Node), a Web Serial SerialPort, or a SerialLike. */
export class RNodeRoad extends Road {
  constructor(port: string | SerialLike | unknown, opts: RNodeOptions)
  config: { frequency: number; bandwidth: number; txpower: number; sf: number; cr: number }
  firmware: [number, number] | null
  platform: number | null
  mcu: number | null
  radioState: number | null
  /** dBm of the last received frame */
  rssi: number | null
  /** dB of the last received frame */
  snr: number | null
  errors: string[]
}
