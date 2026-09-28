# TODO (cosechat-js)

State: the data library (COSE, HPKE, identities, ratchets, messages,
announces, links, resources, propagation, packets, road auth, contacts), the
Node, and the memory / WebSocket / UDP / shared roads are ported from the
Python reference and pass all of its vectors. The JS echo bot passes
`interop/live.py` 6/6 (WebSocket, UDP). The web example has been driven end to
end in headless Chrome through both a JS relay and a Python relay /
propagation node, with a Python peer.

## Next

- [ ] **JS-generated vectors checked by Python.** Add `generate()` to
      `src/vectors.js`, mirroring `cosechat/vectors.py` (fresh keys, every
      COSE op, messages, announces, links, road auth), plus a script that writes
      the file. Then `uv run cosechat check <file>` in the Python repo must
      report no failures. `exact()` already exists.
- [ ] **RNode road** (`roads/rnode.js` + `roads/kiss.js`), over Web Serial in
      browsers and `serialport` in Node. Port `cosechat/roads/rnode.py`;
      bitrate from the radio settings so the announce budget applies.
- [ ] **CLI** (`bin/cosechat.js`): keygen, info, vectors, check, as in the
      Python `cosechat` tool.
- [ ] Storage examples for Node (file-backed ratchets and store, like
      `examples/storage.py`) and IndexedDB for browsers (the web example uses
      localStorage).
- [ ] TypeScript declarations (`.d.ts`) for the public API.
- [ ] Publish to npm (ask first).

## Notes for whoever picks this up

- CBOR map keys are sorted like cbor2's canonical mode (shorter encoded key
  first, then bytewise). cborg's default sorter orders differently. Also,
  cborg's encoder is not reentrant: never call `encode` from inside a
  `mapSorter` (see `src/cbor.js`).
- HPKE (`src/hpke.js`): DHKEM suites use the RFC 9180 two-stage key schedule.
  X-Wing and ML-KEM use the one-stage SHAKE256 schedule from
  draft-ietf-hpke-hpke, and neither `@hpke/core` nor hpke-rs supports it.
  Both are checked against the Python/OpenSSL vectors.
- Timers: every node timer goes through `Node._after`, and `stop()` clears
  them. An awaited promise whose timer was cleared never resolves, which is how
  tasks are cancelled.
- A `WebSocketClientRoad` drops frames while it is down (as in Python), so
  announce from `onStatus` once it is up, not right after `start()`.
