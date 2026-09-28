// UDP road (Node only). Each frame is one datagram. By default it broadcasts
// on the local network, like Reticulum's UDPInterface; give `peers` for unicast.

import { createSocket } from 'node:dgram'
import { sha256 } from '@noble/hashes/sha2.js'
import { toHex } from '../bytes.js'
import { Road } from './road.js'

export const DEFAULT_PORT = 4242

export class UDPRoad extends Road {
  static MTU = 1200 // under common path MTUs so datagrams are not IP-fragmented

  constructor({ host = '0.0.0.0', port = DEFAULT_PORT, peers = null, ...opts } = {}) {
    super({ name: `udp:${port}`, ...opts })
    this.host = host
    this._port = port
    this.peers = peers ?? [['255.255.255.255', port]]
    this._sock = null
    this._sent = [] // hashes of our own recent frames (broadcasts come back)
  }

  get port() {
    return this._sock ? this._sock.address().port : this._port
  }

  async start() {
    const sock = createSocket({ type: 'udp4', reuseAddr: true })
    await new Promise((resolve, reject) => {
      sock.once('error', reject)
      sock.bind(this._port, this.host, () => {
        sock.off('error', reject)
        sock.setBroadcast(true)
        resolve()
      })
    })
    sock.on('message', (data) => this._received(new Uint8Array(data)))
    sock.on('error', () => {})
    this._sock = sock
    await super.start()
  }

  async stop() {
    await super.stop()
    if (this._sock) this._sock.close()
    this._sock = null
  }

  async send(frame) {
    if (!this._sock) return
    this._sent.push(toHex(sha256(frame).slice(0, 8)))
    if (this._sent.length > 64) this._sent.shift()
    for (const [host, port] of this.peers) this._sock.send(frame, port, host)
  }

  _received(data) {
    if (this._sent.includes(toHex(sha256(data).slice(0, 8)))) return
    this._deliver(data)
  }
}
