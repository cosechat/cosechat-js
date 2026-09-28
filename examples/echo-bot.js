// Echo bot: whatever you send it, it sends back (sealed or over a link, as it
// came), and it echoes resources too. It announces itself periodically.
// This is the bot the Python interop/live.py runner checks.
//
//   node examples/echo-bot.js                                  # join the web example's room
//   node examples/echo-bot.js --ws wss://host/ws/room          # join another room
//   node examples/echo-bot.js --ws-server 47243                # WebSocket server road (for interop/live.py)
//   node examples/echo-bot.js --udp 47002 --udp-peer 127.0.0.1:47001
//   node examples/echo-bot.js --rnode /dev/ttyUSB0 --freq 868000000 --sf 8   # LoRa (npm i serialport)
//
// Keys are kept with examples/storage.js in ~/.cosechat/echo-bot-js (ratchets
// in echo-bot-js.ratchets): the address stays the same across restarts,
// ratchets rotate every 30 minutes and are deleted after 10 days. --lock
// encrypts them at rest (passphrase from COSECHAT_PASSPHRASE). --ephemeral
// keeps everything in memory instead.

import { join } from 'node:path'
import { parseArgs } from 'node:util'
import { Identity, Node } from '../src/index.js'
import { HOME, announceForever, loadIdentity, ratchetsFor } from './storage.js'
import { toHex } from '../src/bytes.js'
import { RNodeRoad } from '../src/roads/rnode.js'
import { UDPRoad } from '../src/roads/udp.js'
import { WebSocketClientRoad, WebSocketServerRoad } from '../src/roads/websocket.js'

const { values: a } = parseArgs({
  options: {
    'ws-server': { type: 'string', multiple: true },
    ws: { type: 'string', multiple: true },
    udp: { type: 'string' },
    'udp-peer': { type: 'string', multiple: true },
    rnode: { type: 'string', multiple: true },
    freq: { type: 'string' },
    bw: { type: 'string', default: '125000' },
    sf: { type: 'string', default: '8' },
    cr: { type: 'string', default: '5' },
    txp: { type: 'string', default: '7' },
    identity: { type: 'string', default: join(HOME, 'echo-bot-js') },
    lock: { type: 'boolean' },
    ephemeral: { type: 'boolean' },
    suite: { type: 'string', default: 'pq' },
    name: { type: 'string', default: 'echo-bot (js)' },
    interval: { type: 'string', default: '1800' },
    verbose: { type: 'boolean', short: 'v' }
  }
})

const passphrase = a.lock ? process.env.COSECHAT_PASSPHRASE : null
if (a.lock && !passphrase) throw new Error('--lock needs the passphrase in COSECHAT_PASSPHRASE')
const identity = a.ephemeral ? Identity.generate(a.suite) : loadIdentity(a.identity, { suite: a.suite, passphrase })
const ratchets = a.ephemeral ? null : ratchetsFor(a.identity, identity, { passphrase })
const node = new Node({ identity, ratchets, appData: new Map([['name', a.name]]), quantumSafeOnly: identity.quantumSafe, log: a.verbose ? console.log : null })
// with no road given, join the room the web example uses (a broadcast worker)
const ROOM = 'wss://signal.konsumer.workers.dev/ws/cosechat'
if (!a['ws-server'] && !a.ws && !a.udp && !a.rnode) a.ws = [ROOM]
for (const port of a['ws-server'] || []) node.addRoad(new WebSocketServerRoad({ port: Number(port) }))
for (const url of a.ws || []) {
  const road = new WebSocketClientRoad(url)
  // frames sent while a client road is down are dropped: announce once it is up
  road.onStatus = (up) => up && node.announce({ full: true })
  node.addRoad(road)
}
if (a.udp) {
  const peers = (a['udp-peer'] || []).map((p) => {
    const i = p.lastIndexOf(':')
    return [p.slice(0, i) || '127.0.0.1', Number(p.slice(i + 1))]
  })
  node.addRoad(new UDPRoad({ port: Number(a.udp), peers: peers.length ? peers : null }))
}
for (const port of a.rnode || []) {
  if (!a.freq) throw new Error('--rnode needs --freq (Hz, as your region allows)')
  node.addRoad(new RNodeRoad(port, { frequency: Number(a.freq), bandwidth: Number(a.bw), sf: Number(a.sf), cr: Number(a.cr), txpower: Number(a.txp) }))
}

node.onMessage(async (m) => {
  console.log(`${toHex(m.sender).slice(0, 12)}: ${JSON.stringify(m.content)}`)
  try {
    await node.send(m.sender, m.content, { title: m.title, fields: m.fields })
  } catch (e) {
    console.log(`  could not reply: ${e.message}`)
  }
})

node.onResource(async (r) => {
  console.log(`${toHex(r.peer).slice(0, 12)}: resource of ${r.data.length} bytes`)
  await node.sendResource(r.peer, r.data, { meta: r.meta })
})

node.onAnnounce((ann, path) => {
  const name = ann.appData instanceof Map ? ann.appData.get('name') : null
  console.log(`* ${name || '?'} ${toHex(ann.address)} (${path.hops} hop(s))`)
})

try {
  await node.start()
} catch (e) {
  console.error(`could not start: ${e.message}`)
  process.exit(1)
}
console.log(`echo bot ${toHex(node.address)} on ${node.lanes.map((l) => l.road.name).join(', ')}, announcing every ${a.interval}s`)
announceForever(node, Number(a.interval), ratchets)
process.on('SIGINT', async () => {
  await node.stop()
  process.exit(0)
})
