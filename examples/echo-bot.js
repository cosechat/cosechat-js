// Echo bot: whatever you send it, it sends back (sealed or over a link, as it
// came), and it echoes resources too. It announces itself periodically.
// This is the bot the Python interop/live.py runner checks.
//
//   node examples/echo-bot.js --ws-server 4243                 # WebSocket server road
//   node examples/echo-bot.js --udp 47002 --udp-peer 127.0.0.1:47001
//   node examples/echo-bot.js --ws ws://host:4243              # join a relay
//
// --identity FILE keeps the keyset (private keys: keep it safe) so the
// address survives restarts. Ratchets live in memory only.

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { parseArgs } from 'node:util'
import { Identity, Node } from '../src/index.js'
import { toHex } from '../src/bytes.js'
import { UDPRoad } from '../src/roads/udp.js'
import { WebSocketClientRoad, WebSocketServerRoad } from '../src/roads/websocket.js'

const { values: a } = parseArgs({
  options: {
    'ws-server': { type: 'string', multiple: true },
    ws: { type: 'string', multiple: true },
    udp: { type: 'string' },
    'udp-peer': { type: 'string', multiple: true },
    identity: { type: 'string' },
    suite: { type: 'string', default: 'pq' },
    name: { type: 'string', default: 'echo-bot (js)' },
    interval: { type: 'string', default: '1800' },
    verbose: { type: 'boolean', short: 'v' }
  }
})

function loadIdentity() {
  if (a.identity && existsSync(a.identity)) return Identity.fromBytes(new Uint8Array(readFileSync(a.identity)))
  const ident = Identity.generate(a.suite)
  if (a.identity) writeFileSync(a.identity, ident.toBytes(true), { mode: 0o600 })
  return ident
}

const identity = loadIdentity()
const node = new Node({ identity, appData: new Map([['name', a.name]]), quantumSafeOnly: identity.quantumSafe, log: a.verbose ? console.log : null })
for (const port of a['ws-server'] || []) node.addRoad(new WebSocketServerRoad({ port: Number(port) }))
for (const url of a.ws || []) node.addRoad(new WebSocketClientRoad(url))
if (a.udp) {
  const peers = (a['udp-peer'] || []).map((p) => {
    const i = p.lastIndexOf(':')
    return [p.slice(0, i) || '127.0.0.1', Number(p.slice(i + 1))]
  })
  node.addRoad(new UDPRoad({ port: Number(a.udp), peers: peers.length ? peers : null }))
}
if (!node.lanes.length) node.addRoad(new WebSocketServerRoad({ port: 4243 }))

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

await node.start()
console.log(`echo bot ${toHex(node.address)} on ${node.lanes.map((l) => l.road.name).join(', ')}, announcing every ${a.interval}s`)
const loop = async () => {
  await node.announce()
  setTimeout(loop, Number(a.interval) * 1000)
}
loop()
process.on('SIGINT', async () => {
  await node.stop()
  process.exit(0)
})
