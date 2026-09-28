import { Road, type RoadOptions } from './road.js'

/** In-process hub: every road on it hears every other. */
export class MemoryHub {
  constructor(opts?: { loss?: number; latency?: number })
  loss: number
  latency: number
  roads: MemoryRoad[]
  frames: number
  road(opts?: RoadOptions): MemoryRoad
}
export class MemoryRoad extends Road {
  constructor(hub: MemoryHub, opts?: RoadOptions)
  hub: MemoryHub
}
