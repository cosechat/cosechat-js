# TODO (cosechat-js)

State: a complete port of the Python reference (`../cosechat-py`) for Node and
browsers:

- the data library (COSE, HPKE, identities, ratchets, messages, announces,
  links, resources, propagation, packets, road auth, contacts)
- the Node
- roads: memory, WebSocket, UDP, shared, and RNode (serialport / Web Serial)
- a CLI, TypeScript declarations, and storage examples for Node (files) and
  browsers (IndexedDB, optional passphrase lock)

Conformance holds both ways:

- it passes every Python vector, and Python and stock wolfCOSE (40/40) accept
  its generated vectors
- the echo bot passes `interop/live.py` 6/6 (WebSocket, UDP)
- the web example works end to end through Python and JS relays, including
  LoRa between browsers over emulated RNodes

## Left

- [ ] **Real RNode hardware.** The road is tested against an emulated RNode
      (Node and Web Serial) only, as is the Python one (its TODO item 19).
- [ ] **GitHub remote and CI** (ask the user first). `.github/workflows/ci.yml`
      is ready: npm test, types and prettier on Node 22 and 24.
- [ ] **Publish to npm** (ask the user first). `npm pack --dry-run` gives a
      clean package: src, bin, types, README, LICENSE.
- [ ] Later, as in the Python TODO: group destinations, more roads (TCP, BLE),
      stamps.

## Notes for whoever picks this up

- Formatting: `npm run fmt` (prettier with `.prettierrc`); commits are one
  line, at most 40 characters, straight to `main` until there is a remote.
- CBOR map keys are sorted like cbor2's canonical mode (shorter encoded key
  first, then bytewise). cborg's default sorter orders differently. Also,
  cborg's encoder is not reentrant: never call `encode` from inside a
  `mapSorter` (see `src/cbor.js`).
- In Node, cborg sometimes returns a pooled `Buffer`, whose `slice()` is a
  view and not a copy. `encode()` always returns a plain `Uint8Array` for that
  reason; keep it that way.
- HPKE (`src/hpke.js`): DHKEM suites use the RFC 9180 two-stage key schedule;
  X-Wing and ML-KEM use the one-stage SHAKE256 schedule from
  draft-ietf-hpke-hpke, which neither `@hpke/core` nor hpke-rs supports. Both
  are checked against the Python/OpenSSL vectors.
- Timers: every node timer goes through `Node._after`, and `stop()` clears
  them. An awaited promise whose timer was cleared never resolves, which is how
  tasks are cancelled.
- A `WebSocketClientRoad` drops frames while it is down (as in Python), so
  announce from `onStatus` once it is up, not right after `start()`.
- A `WebSocketServerRoad` is one shared medium: it repeats every client's frame
  to the other clients (SPEC §10). Python does the same.
- After changing an export, update `types/` too: `test/types.test.js` fails
  otherwise.
