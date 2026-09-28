// In-process road for tests and simulations: every road on a hub hears every other.

import { Road } from './road.js'

export class MemoryHub {
  constructor({ loss = 0, latency = 0 } = {}) {
    this.loss = loss
    this.latency = latency // seconds
    this.roads = []
    this.frames = 0
  }

  road(opts = {}) {
    return new MemoryRoad(this, opts)
  }
}

export class MemoryRoad extends Road {
  constructor(hub, opts = {}) {
    super(opts)
    this.hub = hub
    hub.roads.push(this)
  }

  async send(frame) {
    if (frame.length > this.mtu) throw new Error(`${this}: frame of ${frame.length} bytes exceeds MTU ${this.mtu}`)
    this.hub.frames++
    for (const r of this.hub.roads) {
      if (r === this || !r.online) continue
      if (this.hub.loss && Math.random() < this.hub.loss) continue
      const copy = frame.slice()
      setTimeout(() => r._deliver(copy), this.hub.latency * 1000)
    }
  }
}
