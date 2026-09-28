import { Road, type RoadOptions } from './road.js'

export const WS_MTU: number

/** Browsers and Node 22+; reconnects when dropped. Frames sent while down are dropped. */
export class WebSocketClientRoad extends Road {
  constructor(url: string, opts?: RoadOptions & { WebSocket?: unknown; reconnect?: number })
  url: string
  reconnect: number
  connected: boolean
  onStatus: ((connected: boolean) => void) | null
}

/** Node only (the `ws` package). One shared medium: clients hear each other. */
export class WebSocketServerRoad extends Road {
  constructor(opts?: RoadOptions & { host?: string; port?: number; server?: unknown })
  readonly port: number
  clients: Set<unknown>
}
