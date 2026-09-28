// Serves the web example (the page loads cosechat straight from src/ with an
// import map, no bundler). Optionally runs a relay the page can connect to.
//
//   node examples/web/serve.js                  # page on http://localhost:8080
//   node examples/web/serve.js --relay          # + JS transport node on ws://localhost:4243
//   node examples/web/serve.js --relay --propagate
//
// Or use the Python reference as the relay instead of --relay:
//   uv run examples/chat.py --ws-server 4243 --transport

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, join, normalize } from 'node:path'
import { parseArgs } from 'node:util'

const { values: a } = parseArgs({
  options: {
    port: { type: 'string', default: '8080' },
    relay: { type: 'boolean' },
    'relay-port': { type: 'string', default: '4243' },
    propagate: { type: 'boolean' },
    passphrase: { type: 'string' },
    mode: { type: 'string', default: 'mac' }
  }
})

const root = new URL('../..', import.meta.url).pathname
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' }
// only these trees are served
const ALLOWED = ['examples/web/', 'src/', 'node_modules/@noble/', 'node_modules/cborg/']

const server = createServer(async (req, res) => {
  let path = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '')
  if (path === '' || path === 'index.html' || path === 'examples/web' || path === 'examples/web/') {
    res.writeHead(302, { location: '/examples/web/index.html' }).end()
    return
  }
  path = normalize(path)
  if (!ALLOWED.some((p) => path.startsWith(p))) {
    res.writeHead(404).end('not found')
    return
  }
  try {
    const body = await readFile(join(root, path))
    res.writeHead(200, { 'content-type': TYPES[extname(path)] || 'application/octet-stream', 'cache-control': 'no-cache' })
    res.end(body)
  } catch {
    res.writeHead(404).end('not found')
  }
})
server.listen(Number(a.port), () => console.log(`page on http://localhost:${a.port}`))

if (a.relay) {
  const { Node, RoadAuth } = await import('../../src/index.js')
  const { WebSocketServerRoad } = await import('../../src/roads/websocket.js')
  const { toHex } = await import('../../src/bytes.js')
  // a relay only forwards (and, with --propagate, holds) ciphertext; it accepts
  // pre-quantum peers too so every suite in the page can be tried
  const relay = new Node({ transport: true, propagate: a.propagate, quantumSafeOnly: false, appData: new Map([['name', a.propagate ? 'js relay (propagation)' : 'js relay']]), rebroadcastMinInterval: 5 })
  const auth = a.passphrase ? RoadAuth.fromPassphrase(a.passphrase, a.mode) : null
  relay.addRoad(new WebSocketServerRoad({ port: Number(a['relay-port']) }), auth)
  relay.onAnnounce((ann, path) => console.log(`* ${ann.appData instanceof Map ? ann.appData.get('name') : '?'} ${toHex(ann.address)} (${path.hops} hop(s))`))
  await relay.start()
  await relay.announce()
  setInterval(() => relay.announce(), 600e3)
  console.log(`relay ${toHex(relay.address)} on ws://localhost:${a['relay-port']}${a.propagate ? ' (propagation node)' : ''}`)
}
