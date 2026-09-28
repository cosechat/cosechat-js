// Wi-Fi raw and BLE roads: codec tests + node integration via MemoryHub.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { MemoryHub } from '../src/roads/memory.js'
import { RawWifiRoad, encode as wEncode, decode as wDecode, WIFI_MTU } from '../src/roads/wifi_raw.js'
import { encode as bEncode, decode as bDecode, BLE_MTU, COMPANY_ID, BLERoad } from '../src/roads/ble.js'
import { Node } from '../src/node.js'
import { Identity } from '../src/identity.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function until(cond, timeout = 10) {
  const end = Date.now() + timeout * 1000
  while (!cond()) {
    if (Date.now() > end) throw new Error('condition not reached')
    await sleep(10)
  }
}
const inbox = (node) => {
  const box = []
  node.onMessage((m) => box.push(m))
  return box
}
const hasPath = (n, other) => Boolean(n.path(other.address))

// --- Codec: 802.11 action frames ---

test('wifi raw codec roundtrip', () => {
  const payload = new Uint8Array(240).fill(0x42)
  const frame = wEncode(payload)
  assert.equal(frame[0] & 0xfc, 0xd0)
  assert.deepEqual(frame.slice(4, 10), new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))
  assert.equal(frame[24], 127)
  assert.equal(frame[25], 0xcc)
  const out = wDecode(frame)
  assert.deepEqual(out, payload)
})

test('wifi raw oversized rejected', () => {
  assert.throws(() => wEncode(new Uint8Array(WIFI_MTU + 1)))
})

test('wifi raw decode bad data', () => {
  assert.equal(wDecode(new Uint8Array(10)), null)
  assert.equal(wDecode(new Uint8Array(30).fill(0x00)), null)
})

test('wifi raw MTU constant', () => {
  assert.equal(WIFI_MTU, 252)
})

// --- Codec: BLE manufacturer data ---

test('ble codec roundtrip', () => {
  const frame = new Uint8Array(100).fill(0x99)
  const ad = bEncode(frame)
  assert.equal(ad[0], 3 + 100)
  assert.equal(ad[1], 0xff)
  const cid = ad[2] | (ad[3] << 8)
  assert.equal(cid, COMPANY_ID)
  const out = bDecode(ad)
  assert.deepEqual(out, frame)
})

test('ble oversized rejected', () => {
  assert.throws(() => bEncode(new Uint8Array(BLE_MTU + 1)))
})

test('ble decode bad data', () => {
  assert.equal(bDecode(new Uint8Array(4)), null)
  assert.equal(bDecode(new Uint8Array([4, 0xff, 0, 0, 0, 0, 0])), null)
})

test('ble MTU constant', () => {
  assert.equal(BLE_MTU, 247)
})

// --- Node integration via MemoryHub ---

test('two nodes via wifi MTU on MemoryHub', async () => {
  const hub = new MemoryHub()
  const a = new Node({ rebroadcastDelay: 0 })
  const b = new Node({ rebroadcastDelay: 0 })
  a.addRoad(hub.road({ mtu: WIFI_MTU }))
  b.addRoad(hub.road({ mtu: WIFI_MTU }))
  const box = inbox(b)
  await a.start()
  await b.start()
  await a.announce()
  await b.announce()
  await until(() => hasPath(a, b) && hasPath(b, a))
  await a.send(b.address, 'wifi-mtu-ok')
  await until(() => box.length >= 1)
  await a.stop()
  await b.stop()
  assert.equal(box[0].content, 'wifi-mtu-ok')
})

test('two nodes via ble MTU on MemoryHub', async () => {
  const hub = new MemoryHub()
  const a = new Node({ rebroadcastDelay: 0 })
  const b = new Node({ rebroadcastDelay: 0 })
  a.addRoad(hub.road({ mtu: BLE_MTU }))
  b.addRoad(hub.road({ mtu: BLE_MTU }))
  const box = inbox(b)
  await a.start()
  await b.start()
  await a.announce()
  await b.announce()
  await until(() => hasPath(a, b) && hasPath(b, a))
  await a.send(b.address, 'ble-mtu-ok')
  await until(() => box.length >= 1)
  await a.stop()
  await b.stop()
  assert.equal(box[0].content, 'ble-mtu-ok')
})

test('different MTUs isolated', async () => {
  const h1 = new MemoryHub()
  const h2 = new MemoryHub()
  const a = new Node({ rebroadcastDelay: 0 })
  const b = new Node({ rebroadcastDelay: 0 })
  a.addRoad(h1.road({ mtu: WIFI_MTU }))
  b.addRoad(h2.road({ mtu: BLE_MTU }))
  const box = inbox(b)
  await a.start()
  await b.start()
  await a.announce()
  await b.announce()
  await sleep(200)
  await a.stop()
  await b.stop()
  assert.equal(box.length, 0)
  assert.equal(hasPath(a, b), false)
})

test('transport bridging two MemoryHubs', async () => {
  const wHub = new MemoryHub()
  const bHub = new MemoryHub()
  const aNode = new Node({ rebroadcastDelay: 0 })
  const cNode = new Node({ rebroadcastDelay: 0 })
  aNode.addRoad(wHub.road({ mtu: WIFI_MTU }))
  cNode.addRoad(wHub.road({ mtu: WIFI_MTU }))
  const transport = new Node({ transport: true, rebroadcastDelay: 0 })
  transport.addRoad(wHub.road())
  transport.addRoad(bHub.road())
  const bNode = new Node({ rebroadcastDelay: 0 })
  bNode.addRoad(bHub.road({ mtu: BLE_MTU }))
  const box = inbox(bNode)
  await aNode.start()
  await cNode.start()
  await transport.start()
  await bNode.start()
  await aNode.announce()
  await bNode.announce()
  await until(() => hasPath(aNode, bNode))
  await until(() => hasPath(bNode, aNode))
  await aNode.send(bNode.address, 'via-transport')
  await until(() => box.length >= 1)
  await aNode.stop()
  await cNode.stop()
  await transport.stop()
  await bNode.stop()
  assert.equal(box[0].content, 'via-transport')
})

test('RawWifiRoad has no transport in Node and says so', async () => {
  const road = new RawWifiRoad()
  assert.equal(road.mtu, WIFI_MTU)
  assert.equal(road.name, 'wifi-raw')
  assert.equal(road.interface, null)
  await assert.rejects(() => road.start(), /MemoryHub/)
})

test('BLERoad with no adapter', () => {
  const road = new BLERoad()
  assert.equal(road.mtu, BLE_MTU)
  assert.equal(road.name, 'ble')
})
