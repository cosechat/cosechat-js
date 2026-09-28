import type { Bytes } from '../bytes.js'

export interface RoadOptions {
  name?: string | null
  mtu?: number | null
  /** bits per second, if slow enough that announces need a budget */
  bitrate?: number | null
}

/** A broadcast medium that moves opaque frames. */
export class Road {
  constructor(opts?: RoadOptions)
  name: string
  mtu: number
  bitrate: number | null
  online: boolean
  onFrame: ((frame: Bytes) => void) | null
  start(): Promise<void>
  stop(): Promise<void>
  send(frame: Bytes): Promise<void>
  protected _deliver(frame: Bytes): void
}
