// WebSocket roads (binary messages, one frame each).
//
//   WebSocketClientRoad  connects to a server and reconnects when dropped.
//                        Works in browsers (global WebSocket) and in Node
//                        (global WebSocket in Node 22+, or pass the `ws` class).
//   WebSocketServerRoad  Node only, needs the `ws` package: accepts many peers.
//                        It is one shared medium, like a LAN: a frame from one
//                        client reaches the node behind the server and every
//                        other client. With transport: true that node also
//                        links the clients to the rest of the mesh.

import { Road } from './road.js'

export const WS_MTU = 1 << 20

const toBytes = async (data) => {
  if (data instanceof Uint8Array) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
  if (data instanceof ArrayBuffer) return new Uint8Array(data)
  if (Array.isArray(data)) return new Uint8Array(Buffer.concat(data)) // ws fragments
  if (typeof Blob !== 'undefined' && data instanceof Blob) return new Uint8Array(await data.arrayBuffer())
  return null // text messages are not frames
}

export class WebSocketClientRoad extends Road {
  static MTU = WS_MTU

  constructor(url, { WebSocket: WS = globalThis.WebSocket, reconnect = 2, ...opts } = {}) {
    super({ name: url, ...opts })
    if (!WS) throw new Error('no WebSocket available: pass { WebSocket } (e.g. from the ws package)')
    this.url = url
    this.WS = WS
    this.reconnect = reconnect // seconds
    this._ws = null
    this._timer = null
    this.connected = false
    this.onStatus = null // (connected: boolean) => void
  }

  async start() {
    await super.start()
    this._connect()
  }

  async stop() {
    await super.stop()
    clearTimeout(this._timer)
    if (this._ws) this._ws.close()
    this._ws = null
  }

  _status(up) {
    this.connected = up
    if (this.onStatus) this.onStatus(up)
  }

  _connect() {
    if (!this.online) return
    let ws
    try {
      ws = new this.WS(this.url)
    } catch {
      this._timer = setTimeout(() => this._connect(), this.reconnect * 1000)
      return
    }
    ws.binaryType = 'arraybuffer'
    this._ws = ws
    ws.onopen = () => this._status(true)
    ws.onmessage = async (ev) => {
      const b = await toBytes(ev.data)
      if (b) this._deliver(b)
    }
    ws.onerror = () => {}
    ws.onclose = () => {
      if (this._ws === ws) this._ws = null
      if (this.connected) this._status(false)
      if (this.online) this._timer = setTimeout(() => this._connect(), this.reconnect * 1000)
    }
  }

  async send(frame) {
    const ws = this._ws
    if (!ws || ws.readyState !== 1) return
    try {
      ws.send(frame)
    } catch {}
  }
}

export class WebSocketServerRoad extends Road {
  static MTU = WS_MTU

  constructor({ host = '0.0.0.0', port = 4243, server = null, ...opts } = {}) {
    super({ name: `ws-server:${port}`, ...opts })
    this.host = host
    this._port = port
    this._httpServer = server // attach to an existing http(s) server instead
    this._wss = null
    this.clients = new Set()
  }

  get port() {
    const a = this._wss?.address?.()
    return a && typeof a === 'object' ? a.port : this._port
  }

  async start() {
    const { WebSocketServer } = await import('ws')
    await new Promise((resolve, reject) => {
      const opts = this._httpServer ? { server: this._httpServer } : { host: this.host, port: this._port }
      this._wss = new WebSocketServer({ ...opts, maxPayload: this.mtu })
      this._wss.on('connection', (ws) => {
        this.clients.add(ws)
        ws.on('message', async (data, isBinary) => {
          if (!isBinary) return
          const b = await toBytes(data)
          if (!b) return
          this._deliver(b)
          this._send(b, ws) // the other clients hear it too
        })
        ws.on('close', () => this.clients.delete(ws))
        ws.on('error', () => this.clients.delete(ws))
      })
      if (this._httpServer) resolve()
      else {
        this._wss.on('listening', resolve)
        this._wss.on('error', reject)
      }
    })
    await super.start()
  }

  async stop() {
    await super.stop()
    for (const ws of this.clients) ws.terminate()
    this.clients.clear()
    if (this._wss) await new Promise((resolve) => this._wss.close(() => resolve()))
    this._wss = null
  }

  async send(frame) {
    this._send(frame)
  }

  _send(frame, exclude = null) {
    for (const ws of this.clients) {
      if (ws === exclude) continue
      try {
        ws.send(frame)
      } catch {
        this.clients.delete(ws)
      }
    }
  }
}
