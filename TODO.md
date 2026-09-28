# TODO (cosechat-js)

State: a complete port of the Python reference (`../cosechat-py`) for Node and
browsers:

- the data library (COSE, HPKE, identities, ratchets, messages, announces,
  links, resources, propagation, packets, road auth, contacts)
- the Node
- roads: memory, WebSocket, UDP, shared, RNode (serialport / Web Serial), and
  the anonymous ones: wifi_raw (codec only in Node) and ble (BlueZ + dbus-next,
  Linux)
- a CLI, TypeScript declarations, and storage examples for Node (files) and
  browsers (a simple happy-path web tester on a broadcast worker room)

Conformance holds both ways:

- it passes every Python vector, and Python and stock wolfCOSE (40/40) accept
  its generated vectors
- the echo bot passes `interop/live.py` 6/6 (WebSocket, UDP)
- the web tester works end to end through the signal-worker room, with JS and
  Python peers

## Left

- [x] **Real RNode hardware.** Tested over the air on two RNodes with
      `test/rnode.hardware.test.js` (skipped unless two serial RNodes are
      attached; `COSECHAT_RNODE_PORTS`, `COSECHAT_RNODE_FREQ`). Opening the port
      resets the device, so the road retries detect and config until it
      answers.
- [x] **Anonymous broadcast roads.** `roads/ble` advertises and scans through
      BlueZ (`dbus-next`, optional dependency) with the C reference's framing
      (247-byte MTU); the D-Bus path is pinned by a fake-bus test in
      `test/ble.test.js`. Needs an adapter that supports extended advertising,
      and (honest gap vs the ESP32 road) BlueZ always puts the adapter address
      in the advertisement. `roads/wifi_raw` is codec-only in Node: there is no
      AF_PACKET, so it starts with a clear error; use the Python road, a
      native helper behind the same codec, or MemoryHub.
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
