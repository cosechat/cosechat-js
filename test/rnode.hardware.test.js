// Two real RNodes over the air. Skipped unless two serial RNodes are attached.
//
//   COSECHAT_RNODE_PORTS=/dev/ttyUSB0,/dev/ttyUSB1
//   COSECHAT_RNODE_FREQ=868000000   (default 915000000)
//
// Both radios must be the same band and share one config. If the ports exist but
// the radios fail to start (wrong band, cable pulled), the test skips.
//
// Discovery is deliberately one-sided. A post-quantum announce is ~6.5 kB, i.e.
// a dozen LoRa fragments, so one announce holds the radio for many seconds, and
// a radio cannot hear while it transmits. Two nodes announcing at the same time
// therefore miss each other's fragments *and* each other's fragment NACKs, and
// nothing reassembles. So each side announces on its own, then waits for the
// other's burst to leave the air. The nodes also run with announceCap 0 (no
// announce airtime budget, SPEC 9.0) so every announce in the loop really goes
// out instead of queueing behind the first.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'
import { Identity, Node } from '../src/index.js'
import { RNodeError, RNodeRoad } from '../src/roads/rnode.js'

const PATTERNS = [/^tty\.usbserial/, /^cu\.usbserial/, /^ttyUSB/, /^ttyACM/]

// seconds to let one side's announce burst leave the air before the other sends
const BURST = Number(process.env.COSECHAT_RNODE_BURST || 20) * 1000

function findPorts() {
  const env = process.env.COSECHAT_RNODE_PORTS
  if (env)
    return env
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean)
  let names
  try {
    names = readdirSync('/dev')
  } catch {
    return []
  }
  const found = []
  for (const name of names.sort()) if (PATTERNS.some((p) => p.test(name))) found.push(`/dev/${name}`)
  return [...new Set(found)]
}

const PORTS = findPorts()
const FREQ = Number(process.env.COSECHAT_RNODE_FREQ || 915e6)
const skip = PORTS.length < 2 ? `two RNodes on serial ports needed, found ${PORTS}` : false

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// announce one side at a time until each side has the other. This is inherently
// probabilistic: an announce is a burst of fragments, and the other side has to
// be listening for all of it, so it keeps trying until the deadline.
async function discover(a, b, deadlineSeconds = 300) {
  const end = Date.now() + deadlineSeconds * 1000
  while (!(a.known(b.address) && b.known(a.address))) {
    if (Date.now() > end) throw new Error('peers did not discover each other over the air')
    if (!a.known(b.address)) {
      await a.announce()
      await sleep(BURST)
    }
    if (!b.known(a.address)) {
      await b.announce()
      await sleep(BURST)
    }
  }
}

async function until(cond, seconds = 60) {
  const end = Date.now() + seconds * 1000
  while (!cond()) {
    if (Date.now() > end) throw new Error('condition not reached')
    await sleep(50)
  }
}

test('pq message between two RNodes over the air', { skip, timeout: 420_000 }, async (t) => {
  const ra = new RNodeRoad(PORTS[0], { frequency: FREQ, sf: 8, bootDelay: 0.5, timeout: 10 })
  const rb = new RNodeRoad(PORTS[1], { frequency: FREQ, sf: 8, bootDelay: 0.5, timeout: 10 })
  const a = new Node({ identity: Identity.generate('pq'), rebroadcastDelay: 0, announceCap: 0 })
  const b = new Node({ identity: Identity.generate('pq'), rebroadcastDelay: 0, announceCap: 0 })
  a.addRoad(ra)
  b.addRoad(rb)
  const box = []
  b.onMessage((m) => box.push(m))
  try {
    await a.start()
    await b.start()
  } catch (e) {
    await a.stop()
    await b.stop()
    if (e instanceof RNodeError) {
      t.skip(`RNode hardware not usable: ${e.message}`)
      return
    }
    throw e
  }
  try {
    await discover(a, b)
    const sent = await a.send(b.address, 'over the air')
    await until(() => box.length)
    assert.equal(await a.delivered(sent, 60), true)
    assert.equal(box[0].content, 'over the air')
    assert.deepEqual(box[0].sender, a.address)
  } finally {
    await a.stop()
    await b.stop()
  }
})
