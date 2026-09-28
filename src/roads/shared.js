// One physical road, several nodes (several identities on one device):
//   const shared = new SharedRoad(realRoad)
//   chat.addRoad(shared.branch()); bot.addRoad(shared.branch())

import { Road } from './road.js'

export class SharedRoad {
  constructor(road) {
    this.road = road
    this.branches = []
    this._users = 0
    road.onFrame = (frame) => {
      for (const b of this.branches) if (b.online) b._deliver(frame)
    }
  }

  branch(name = null) {
    const b = new Branch(this, name || `${this.road.name}#${this.branches.length}`)
    this.branches.push(b)
    return b
  }

  async _start() {
    if (++this._users === 1) await this.road.start()
  }

  async _stop() {
    if (--this._users === 0) await this.road.stop()
  }
}

export class Branch extends Road {
  constructor(shared, name) {
    super({ name, mtu: shared.road.mtu, bitrate: shared.road.bitrate })
    this.shared = shared
  }

  async start() {
    await this.shared._start()
    await super.start()
  }

  async stop() {
    await super.stop()
    await this.shared._stop()
  }

  async send(frame) {
    for (const b of this.shared.branches) {
      if (b !== this && b.online) {
        const copy = frame.slice()
        queueMicrotask(() => b._deliver(copy)) // siblings on this device
      }
    }
    await this.shared.road.send(frame)
  }
}
