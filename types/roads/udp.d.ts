import { Road, type RoadOptions } from './road.js'

export const DEFAULT_PORT: 4242

/** Node only. Broadcast by default, or unicast to `peers`. */
export class UDPRoad extends Road {
  constructor(opts?: RoadOptions & { host?: string; port?: number; peers?: [string, number][] | null })
  host: string
  peers: [string, number][]
  readonly port: number
}
