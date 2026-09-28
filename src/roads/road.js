// Roads move opaque frames. They know nothing about identities or crypto; a
// Node attaches to any number of them. A road is a broadcast medium: send()
// reaches every peer on it, and received frames are handed to `onFrame`.

export class Road {
  constructor({ name = null, mtu = null, bitrate = null } = {}) {
    this.name = name || this.constructor.name
    // largest frame this road carries in one piece; Node fragments above it
    this.mtu = mtu ?? this.constructor.MTU ?? 500
    // bits per second, if the medium is slow enough that announces need a budget
    this.bitrate = bitrate
    this.onFrame = null
    this.online = false
  }

  toString() {
    return `<${this.constructor.name} ${this.name}>`
  }

  async start() {
    this.online = true
  }

  async stop() {
    this.online = false
  }

  async send(frame) {
    throw new Error('not implemented')
  }

  _deliver(frame) {
    if (!this.onFrame) return
    try {
      this.onFrame(frame)
    } catch (e) {
      console.error(`${this}: frame handler failed`, e)
    }
  }
}
