// Roads over real sockets (localhost).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import WebSocket from 'ws'
import { Node } from '../src/index.js'
import { UDPRoad } from '../src/roads/udp.js'
import { WebSocketClientRoad, WebSocketServerRoad } from '../src/roads/websocket.js'
import { SharedRoad } from '../src/roads/shared.js'
import { MemoryHub } from '../src/roads/memory.js'
import { utf8 } from '../src/bytes.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function until(cond, timeout = 5) {
  const end = Date.now() + timeout * 1000
  while (!cond()) {
    if (Date.now() > end) throw new Error('condition not reached')
    await sleep(10)
  }
}
const connected = (road) => until(() => road.connected)

test('websocket server road is one medium', async () => {
  const server = new WebSocketServerRoad({ host: '127.0.0.1', port: 0 })
  const heard = { server: [], b: [] }
  server.onFrame = (f) => heard.server.push(f)
  await server.start()
  const url = `ws://127.0.0.1:${server.port}`
  const ca = new WebSocketClientRoad(url, { WebSocket })
  const cb = new WebSocketClientRoad(url, { WebSocket })
  ca.onFrame = () => {}
  cb.onFrame = (f) => heard.b.push(f)
  await ca.start()
  await cb.start()
  try {
    await connected(ca)
    await connected(cb)
    await until(() => server.clients.size === 2)
    await ca.send(utf8('frame from a'))
    await until(() => heard.b.length && heard.server.length)
    assert.deepEqual(heard.b, [utf8('frame from a')])
    assert.deepEqual(heard.server, [utf8('frame from a')])
  } finally {
    await ca.stop()
    await cb.stop()
    await server.stop()
  }
})

test('websocket: a reply gets back without a path (b joined after a announced)', async () => {
  const server = new WebSocketServerRoad({ host: '127.0.0.1', port: 0 })
  const hub = new Node({ transport: true, rebroadcastDelay: 0 })
  hub.addRoad(server)
  await hub.start()
  const url = `ws://127.0.0.1:${server.port}`
  const ca = new WebSocketClientRoad(url, { WebSocket })
  const cb = new WebSocketClientRoad(url, { WebSocket })
  const a = new Node({ rebroadcastDelay: 0 })
  const b = new Node({ rebroadcastDelay: 0 })
  a.addRoad(ca)
  b.addRoad(cb)
  try {
    await a.start()
    await connected(ca)
    await a.announce()
    await until(() => hub.path(a.address))
    await b.start()
    await connected(cb)
    await b.announce()
    await until(() => a.path(b.address))
    assert.equal(b.path(a.address), null)
    const m = await a.send(b.address, 'no path back')
    assert.equal(await a.delivered(m, 5), true)
  } finally {
    for (const n of [a, b, hub]) await n.stop()
  }
})

test('udp road carries a message between nodes', async () => {
  const ra = new UDPRoad({ host: '127.0.0.1', port: 47301, peers: [['127.0.0.1', 47302]] })
  const rb = new UDPRoad({ host: '127.0.0.1', port: 47302, peers: [['127.0.0.1', 47301]] })
  const a = new Node({ rebroadcastDelay: 0 })
  const b = new Node({ rebroadcastDelay: 0 })
  a.addRoad(ra)
  b.addRoad(rb)
  const box = []
  b.onMessage((m) => box.push(m))
  try {
    await a.start()
    await b.start()
    await a.announce()
    await b.announce()
    await until(() => a.path(b.address) && b.path(a.address))
    await a.send(b.address, 'over udp')
    await until(() => box.length)
    assert.equal(box[0].content, 'over udp')
  } finally {
    await a.stop()
    await b.stop()
  }
})

test('shared road: two nodes on one road', async () => {
  const hub = new MemoryHub()
  const other = new Node({ rebroadcastDelay: 0 })
  other.addRoad(hub.road())
  const shared = new SharedRoad(hub.road())
  const chat = new Node({ rebroadcastDelay: 0 })
  const bot = new Node({ rebroadcastDelay: 0 })
  chat.addRoad(shared.branch())
  bot.addRoad(shared.branch())
  const box = []
  bot.onMessage((m) => box.push(m))
  const far = []
  other.onMessage((m) => far.push(m))
  try {
    for (const n of [other, chat, bot]) await n.start()
    for (const n of [other, chat, bot]) await n.announce()
    await until(() => chat.path(bot.address) && chat.path(other.address) && other.path(chat.address) && bot.path(chat.address))
    await chat.send(bot.address, 'same device')
    await chat.send(other.address, 'over the road')
    await until(() => box.length && far.length)
  } finally {
    for (const n of [other, chat, bot]) await n.stop()
  }
})
