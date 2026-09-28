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
- the web tester chats with JS and Python peers through a signal-worker room
- key files written by `examples/storage.js` and the Python
  `examples/storage.py` open in either, locked or not

## Use

```js
import { Node } from 'cosechat'
import { WebSocketClientRoad } from 'cosechat/roads/websocket'

const node = new Node({ appData: new Map([['name', 'alice']]) }) // a new pq identity
const road = new WebSocketClientRoad('wss://signal.konsumer.workers.dev/ws/cosechat')
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

| road                                    | where                                      | notes                                                  |
| --------------------------------------- | ------------------------------------------ | ------------------------------------------------------ |
| `roads/memory`                          | anywhere                                   | in-process hub for tests and simulations               |
| `roads/websocket` `WebSocketClientRoad` | browsers, Node 22+                         | reconnects; `onStatus(up)`                             |
| `roads/websocket` `WebSocketServerRoad` | Node (`ws` package)                        | one shared medium: clients hear each other             |
| `roads/udp`                             | Node                                       | broadcast by default, or unicast `peers`               |
| `roads/shared`                          | anywhere                                   | several nodes (identities) on one road                 |
| `roads/rnode`                           | Node (`serialport`), browsers (Web Serial) | LoRa through an [RNode](https://unsigned.io/rnode)     |
| `roads/wifi_raw`                        | anywhere                                   | raw 802.11 action frames: codec only in JS (no AF_PACKET) |
| `roads/ble`                             | Linux                                      | anonymous BLE extended advertising (BlueZ + `dbus-next`) |

```js
import { RNodeRoad } from 'cosechat/roads/rnode'
node.addRoad(new RNodeRoad('/dev/ttyUSB0', { frequency: 868e6, sf: 8 })) // Node: npm i serialport
node.addRoad(new RNodeRoad(await navigator.serial.requestPort(), { frequency: 868e6 })) // browser
```

The RNode road takes its bitrate from the radio settings, so announces stay
within their airtime budget. It is tested against an emulated RNode and, when
two serial RNodes are attached, over the air
(`test/rnode.hardware.test.js`; `COSECHAT_RNODE_PORTS`, `COSECHAT_RNODE_FREQ`;
skipped otherwise).

The web example and `examples/echo-bot.js` default to the same broadcast room
(`wss://signal.konsumer.workers.dev/ws/cosechat`). To reach a LoRa mesh from a
browser, run the Python bridge on that room:
`uv run ../cosechat-py/examples/lora_gateway.py <serialport> --freq <Hz>`. It
is a transport node, so announces and messages cross between the room and the
radio; see [../cosechat-py/examples/README.md](../cosechat-py/examples/README.md).

The two *anonymous* roads go out with no association and no connection, like
LoRa. `roads/ble` is real on Linux: both directions go through BlueZ's D-Bus
API (`npm i dbus-next` — pure JS, no build step), and the adapter must support
extended advertising (BlueZ reports the ceiling as
`LEAdvertisingManager1.SupportedCapabilities.MaxAdvLen`; the road needs 251).
One honest difference from the ESP32 reference: BlueZ always puts the adapter
address in the advertisement, so a host node is not address-less the way
`road_ble.cpp`'s anonymous advertisement is. `roads/wifi_raw` is codec-only in
JS — Node exposes no AF_PACKET — so for that medium use the Python road, a
native helper behind the same codec, or `MemoryHub`. Both roads are MTU-matched
to the C reference (247 and 252), so a custom transport built on the exported
codec interoperates with an ESP32.

## Examples

**Web app** (`examples/web/`): a simple tester for the happy path, with
Tailwind + daisyUI, loading the library straight from `src/` through an import
map. When it loads, it:

1. makes an identity (kept in IndexedDB)
2. joins a room on [signal-worker](https://github.com/konsumer/signal-worker)
   (`wss://signal.konsumer.workers.dev/ws/cosechat`)
3. announces itself and lists everyone else who announces

Then you pick someone and chat, with delivery receipts. Picking a peer opens a
**link** to them: on a slow radio a sealed message is ~10 fragments and one
lost fragment costs the whole message, while over a link each message is a
single frame.

```sh
npm install
npm start          # page on http://localhost:8080, with live reload
npm run echo-bot   # optional: a bot in the same room that echoes what you send it
```

It is also published to GitHub Pages on every push to main
(<https://cosechat.github.io/cosechat-js/>, from `.github/workflows/pages.yml`).
`npm run build:web` builds the same static site into `_site/`: the page, `src/`,
and the packages its import map points at.

Open the page in two browsers (or one private window) to chat between them.
The worker is a Cloudflare worker that repeats every WebSocket message to
everyone else in the room. It's a shared medium, so the pages talk to each
other directly, and the worker sees only ciphertext and destination
addresses. A peer that was already in the room before you joined shows up at
its next announce (every 30 minutes), or right away if you **Find** its
address. `window.cosechat` holds the page state, including the node, for
poking at from devtools.

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
                      # (real-RNode test runs only with two RNodes attached)
npm run types         # type-check the declarations
npm run sync-vectors  # copy vectors from ../cosechat-py/tests/vectors
npm run fmt           # prettier (see .prettierrc)
```

See [TODO.md](TODO.md) for what is left.
