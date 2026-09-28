# cosechat (JavaScript)

Post-quantum mesh messaging in the spirit of
[Reticulum](https://github.com/markqvist/Reticulum) and
[LXMF](https://github.com/markqvist/LXMF), rebuilt from standards: CBOR, COSE
(Sign1 / Sign / Mac0 / Mac / Encrypt0 / Encrypt), COSE-HPKE with X-Wing
(ML-KEM-768 + X25519), and ML-DSA signatures. For Node and browsers.

This is a port of the Python reference (`../cosechat-py`), which holds the
spec (`SPEC.md`), the CDDL, the porting notes and the caveats. It is plain
JavaScript (ES modules, no build step, no WASM), with TypeScript declarations.
Every primitive comes from the audited [noble](https://paulmillr.com/noble/)
libraries, and CBOR from [cborg](https://github.com/rvagg/cborg).

Conformance, both ways:

- all Python interop vectors pass (accept, reject and byte-exact): `npm test`
- vectors generated here pass the Python checker (`cosechat check`) and the
  stock wolfCOSE checker (40/40). The tests run the Python check when
  `../cosechat-py` is checked out next to this repo
- the wire-size table (`cosechat sizes`) matches the one in the Python SPEC
- the JS echo bot passes the Python live runner (`interop/live.py`) 6/6 over
  WebSocket and UDP
- the web example works through a Python relay, a Python propagation node and a
  Python peer
- key files written by `examples/storage.js` and the Python
  `examples/storage.py` open in either, locked or not

## Use

```js
import { Node } from 'cosechat'
import { WebSocketClientRoad } from 'cosechat/roads/websocket'

const node = new Node({ appData: new Map([['name', 'alice']]) }) // a new pq identity
const road = new WebSocketClientRoad('ws://localhost:4243')
road.onStatus = (up) => up && node.announce({ full: true })
node.addRoad(road)
node.onMessage((m) => console.log(m.sender, m.content))
await node.start()

const m = await node.send(address, 'hello') // finds the path if needed
await node.delivered(m) // true once the recipient's receipt arrives
```

The API mirrors the Python `Node`, with camelCase names and option objects:
`send(to, content, { title, fields, propagate })`, `openLink(peer)`,
`sendResource(peer, bytes, { meta })`, `fetch()`, `rotateRatchet()`,
`contactCard()` / `addContact(card)`, and the `onMessage`, `onAnnounce`,
`onReceipt` and `onResource` handlers. All durations are in seconds. CBOR maps
decode to JS `Map`s, and byte strings are `Uint8Array`s.

The layers under the node can be used on their own: `cosechat/cose`,
`cosechat/message` (seal / unseal / announces), `cosechat/link`,
`cosechat/contact` (address text and `cosechat:` cards).

As in the Python reference, the node is **quantum-safe by default**
(`quantumSafeOnly: true`), and the library does no storage: where identities
and ratchets live is up to the application (the ratchet provider is the
`ratchets` option; see the storage examples below).

## Roads

| road                                    | where                                      | notes                                              |
| --------------------------------------- | ------------------------------------------ | -------------------------------------------------- |
| `roads/memory`                          | anywhere                                   | in-process hub for tests and simulations           |
| `roads/websocket` `WebSocketClientRoad` | browsers, Node 22+                         | reconnects; `onStatus(up)`                         |
| `roads/websocket` `WebSocketServerRoad` | Node (`ws` package)                        | one shared medium: clients hear each other         |
| `roads/udp`                             | Node                                       | broadcast by default, or unicast `peers`           |
| `roads/shared`                          | anywhere                                   | several nodes (identities) on one road             |
| `roads/rnode`                           | Node (`serialport`), browsers (Web Serial) | LoRa through an [RNode](https://unsigned.io/rnode) |

```js
import { RNodeRoad } from 'cosechat/roads/rnode'
node.addRoad(new RNodeRoad('/dev/ttyUSB0', { frequency: 868e6, sf: 8 })) // Node: npm i serialport
node.addRoad(new RNodeRoad(await navigator.serial.requestPort(), { frequency: 868e6 })) // browser
```

The RNode road takes its bitrate from the radio settings, so announces stay
within their airtime budget. It is tested against an emulated RNode only, not
yet on real hardware.

## Examples

**Web app** (`examples/web/`): Tailwind + daisyUI, loading the library straight
from `src/` through an import map. You can:

- make or import an identity
- connect to a relay, announce, and collect announces
- find peers by address, address text or contact card
- chat with receipts
- use links, file transfer (resources), ratchet rotation and road passphrases
- leave a message with a propagation node while a peer is offline, then fetch it

```sh
npm install
npm run web                       # page on http://localhost:8080, JS relay + propagation node on ws://localhost:4243
```

To use the Python reference as the relay instead, serve the page without
`--relay` and run the relay from `../cosechat-py`:

```sh
node examples/web/serve.js
uv run examples/chat.py --ws-server 4243 --transport --propagate
```

Open the page in two browsers (or one private window) to chat between them.
Peers show up when they announce. A peer that was already on the mesh before
you joined shows up at its next announce, or at once with **Find** by its
address. The page keeps its keyset and its newest 8 ratchets in IndexedDB.
**Lock…** encrypts them with a passphrase (scrypt + AES-GCM, the same format
as the storage examples). In Chrome and Edge it can also use an RNode over Web
Serial, with or without a relay. `window.cosechat` holds the page state
(including the node) for poking at from devtools.

**Storage** (`examples/storage.js`): the suggested key storage for Node, in
the same file formats as the Python reference:

- key files written atomically with mode 0600
- optional encryption at rest (scrypt + COSE_Encrypt0)
- a file-backed ratchet provider that rotates every 30 minutes and deletes
  ratchets after 10 days
- a file-backed store for propagation nodes

**Echo bot** (`examples/echo-bot.js`): echoes messages (sealed or over a link)
and resources, with its keys kept by `examples/storage.js`. It is the bot the
Python live runner checks:

```sh
node examples/echo-bot.js --ws-server 47243
uv run ../cosechat-py/interop/live.py <bot address> --ws ws://127.0.0.1:47243
```

## CLI

```sh
npx cosechat keygen -o me.keyset          # new pq identity (--suite hybrid|prequantum)
npx cosechat info me.keyset               # address, address text, algorithms
npx cosechat address <hex or text>        # convert between the two
npx cosechat vectors -o js-vectors.json   # interop vectors from this implementation
npx cosechat check vectors.json           # verify vectors from any implementation
npx cosechat sizes                        # wire sizes (Markdown)
```

## TypeScript

Declarations for every module are in `types/`. They are hand-written, and a
test checks that they match the runtime exports. `npm run types` type-checks
them together with a usage sample.

## Development

```sh
npm test              # vectors, mesh, roads, emulated RNode, storage, interop
npm run types         # type-check the declarations
npm run sync-vectors  # copy vectors from ../cosechat-py/tests/vectors
npm run fmt           # prettier (see .prettierrc)
```

See [TODO.md](TODO.md) for what is left.
