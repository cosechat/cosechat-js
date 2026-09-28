// RNode road against emulated RNodes sharing one "air"; KISS framing.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Identity, Node } from '../src/index.js'
import * as kiss from '../src/roads/kiss.js'
import * as R from '../src/roads/rnode.js'
import { UDPRoad } from '../src/roads/udp.js'
import { equal } from '../src/bytes.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function until(cond, timeout = 10) {
  const end = Date.now() + timeout * 1000
  while (!cond()) {
    if (Date.now() > end) throw new Error('condition not reached')
    await sleep(10)
  }
}

test('KISS round trip with special bytes, fed a byte at a time', () => {
  const data = new Uint8Array([0x00, kiss.FEND, 0x01, kiss.FESC, kiss.FEND, kiss.FESC, 0xff])
  const wire = kiss.frame(R.CMD_DATA, data)
  assert.ok(!wire.slice(1, -1).includes(kiss.FEND))
  const d = new kiss.Decoder()
  const frames = []
  for (let i = 0; i < wire.length; i++) frames.push(...d.feed(wire.slice(i, i + 1)))
  assert.equal(frames.length, 1)
  assert.equal(frames[0][0], R.CMD_DATA)
  assert.ok(equal(frames[0][1], data))
})

// a serial-port stand-in that answers like RNode firmware 1.80
class FakeRNode {
  constructor(air) {
    this.air = air
    air.push(this)
    this.decoder = new kiss.Decoder()
    this.state = {}
    this.on = false
    this.onData = null
  }

  async write(data) {
    for (const [cmd, body] of this.decoder.feed(data)) this.command(cmd, body)
  }

  reply(cmd, body = new Uint8Array()) {
    const f = kiss.frame(cmd, body)
    setTimeout(() => this.onData && this.onData(f), 1)
  }

  command(cmd, body) {
    if (cmd === R.CMD_DETECT && body[0] === R.DETECT_REQ) this.reply(R.CMD_DETECT, new Uint8Array([R.DETECT_RESP]))
    else if (cmd === R.CMD_FW_VERSION) this.reply(R.CMD_FW_VERSION, new Uint8Array([1, 80]))
    else if (cmd === R.CMD_PLATFORM) this.reply(R.CMD_PLATFORM, new Uint8Array([0x80]))
    else if (cmd === R.CMD_MCU) this.reply(R.CMD_MCU, new Uint8Array([0x81]))
    else if ([R.CMD_FREQUENCY, R.CMD_BANDWIDTH, R.CMD_TXPOWER, R.CMD_SF, R.CMD_CR].includes(cmd)) {
      this.state[cmd] = Array.from(body).join(',')
      this.reply(cmd, body)
    } else if (cmd === R.CMD_RADIO_STATE) {
      this.on = body[0] === R.RADIO_STATE_ON
      this.reply(R.CMD_RADIO_STATE, body)
    } else if (cmd === R.CMD_DATA && this.on) {
      assert.ok(body.length <= R.HW_MTU)
      for (const other of this.air) {
        if (other !== this && other.on && JSON.stringify(other.state) === JSON.stringify(this.state)) {
          other.reply(R.CMD_STAT_RSSI, new Uint8Array([157 - 42]))
          other.reply(R.CMD_STAT_SNR, new Uint8Array([40]))
          other.reply(R.CMD_DATA, body)
        }
      }
    }
  }
}

const lora = (air, frequency = 868e6) => new R.RNodeRoad(new FakeRNode(air), { frequency, sf: 9, bootDelay: 0, timeout: 2 })

async function exchange(a, b, content) {
  const box = []
  b.onMessage((m) => box.push(m))
  await a.announce()
  await b.announce()
  await until(() => a.path(b.address) && b.path(a.address))
  await a.send(b.address, content)
  await until(() => box.length)
  return box[0]
}

test('pq message over emulated LoRa', async () => {
  const air = []
  const [ra, rb] = [lora(air), lora(air)]
  const a = new Node({ rebroadcastDelay: 0 })
  const b = new Node({ rebroadcastDelay: 0 })
  a.addRoad(ra)
  b.addRoad(rb)
  await a.start()
  await b.start()
  try {
    assert.deepEqual(ra.firmware, [1, 80])
    assert.deepEqual(ra.reported, ra.config)
    assert.ok(ra.bitrate > 1000 && ra.bitrate < 2000)
    const m = await exchange(a, b, 'post-quantum over LoRa')
    assert.equal(m.content, 'post-quantum over LoRa')
    assert.equal(rb.rssi, -42)
    assert.equal(rb.snr, 10)
  } finally {
    await a.stop()
    await b.stop()
  }
})

test('radios on another frequency hear nothing', async () => {
  const air = []
  const a = new Node({ identity: Identity.generate('prequantum'), quantumSafeOnly: false, rebroadcastDelay: 0 })
  const b = new Node({ identity: Identity.generate('prequantum'), quantumSafeOnly: false, rebroadcastDelay: 0 })
  a.addRoad(lora(air))
  b.addRoad(lora(air, 915e6))
  await a.start()
  await b.start()
  try {
    await b.announce()
    await sleep(200)
    assert.equal(a.path(b.address), null)
  } finally {
    await a.stop()
    await b.stop()
  }
})

test('LoRa and UDP bridged by a transport node', async () => {
  const air = []
  const ug = new UDPRoad({ host: '127.0.0.1', port: 47311, peers: [['127.0.0.1', 47312]] })
  const ub = new UDPRoad({ host: '127.0.0.1', port: 47312, peers: [['127.0.0.1', 47311]] })
  const a = new Node({ rebroadcastDelay: 0 })
  a.addRoad(lora(air))
  const gw = new Node({ transport: true, rebroadcastDelay: 0 })
  gw.addRoad(lora(air))
  gw.addRoad(ug)
  const b = new Node({ rebroadcastDelay: 0 })
  b.addRoad(ub)
  for (const n of [a, gw, b]) await n.start()
  try {
    const m = await exchange(a, b, 'lora to udp')
    assert.equal(m.content, 'lora to udp')
    assert.ok(equal(b.path(a.address).via, gw.address))
  } finally {
    for (const n of [a, gw, b]) await n.stop()
  }
})

test('a device that does not answer detect is an error', async () => {
  const silent = { onData: null, write: async () => {} }
  const road = new R.RNodeRoad(silent, { frequency: 868e6, bootDelay: 0, timeout: 0.2 })
  await assert.rejects(road.start(), /did not answer detect/)
})
