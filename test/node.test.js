// Mesh behaviour over in-memory roads: no radios, no sockets.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Identity, Node, RoadAuth } from '../src/index.js'
import { MemoryHub } from '../src/roads/memory.js'
import { equal, toHex } from '../src/bytes.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function until(cond, timeout = 5) {
  const end = Date.now() + timeout * 1000
  while (!cond()) {
    if (Date.now() > end) throw new Error('condition not reached')
    await sleep(10)
  }
}

function inbox(node) {
  const box = []
  node.onMessage((m) => box.push(m))
  return box
}

function make(hub, { suite = 'pq', mtu = 500, auth = null, ...kw } = {}) {
  const identity = kw.identity || Identity.generate(suite)
  delete kw.identity
  const n = new Node({ identity, quantumSafeOnly: suite !== 'prequantum', rebroadcastDelay: 0.01, ...kw })
  n.addRoad(hub.road({ mtu }), auth)
  return n
}

async function withNodes(nodes, fn) {
  for (const n of nodes) await n.start()
  try {
    await fn()
  } finally {
    for (const n of nodes) await n.stop()
  }
}

const hasPath = (n, other) => Boolean(n.path(other.address))

for (const suite of ['pq', 'prequantum', 'hybrid']) {
  test(`direct neighbours (${suite})`, async () => {
    const hub = new MemoryHub()
    const a = make(hub, { suite })
    const b = make(hub, { suite })
    const box = inbox(b)
    await withNodes([a, b], async () => {
      await a.announce()
      await b.announce({ appData: 'bob' })
      await until(() => hasPath(a, b) && hasPath(b, a))
      assert.equal(a.announces.get(toHex(b.address))[1].appData, 'bob')
      const sent = await a.send(b.address, 'hello bob', { title: 'hi' })
      await until(() => box.length)
      assert.ok(equal(box[0].sender, a.address))
      assert.equal(box[0].content, 'hello bob')
      assert.equal(box[0].title, 'hi')
      assert.ok(equal(box[0].id, sent.id))
      assert.equal(await a.delivered(sent, 5), true)
    })
  })
}

test('multi-hop across roads through transports; transports cannot read', async () => {
  const [h1, h2, h3] = [new MemoryHub(), new MemoryHub(), new MemoryHub()]
  const a = make(h1)
  const t1 = new Node({ transport: true, rebroadcastDelay: 0.01 })
  t1.addRoad(h1.road())
  t1.addRoad(h2.road())
  const t2 = new Node({ transport: true, rebroadcastDelay: 0.01 })
  t2.addRoad(h2.road())
  t2.addRoad(h3.road())
  const b = make(h3)
  const box = inbox(b)
  const peeked = [...inbox(t1), ...inbox(t2)]
  await withNodes([a, t1, t2, b], async () => {
    await a.announce()
    await b.announce()
    await until(() => hasPath(a, b) && hasPath(b, a))
    assert.equal(a.path(b.address).hops, 3)
    assert.ok(equal(a.path(b.address).via, t1.address))
    await a.send(b.address, 'over two transports')
    await until(() => box.length)
  })
  assert.equal(box[0].content, 'over two transports')
  assert.equal(peeked.length, 0)
})

test('path request finds an unannounced destination', async () => {
  const [h1, h2] = [new MemoryHub(), new MemoryHub()]
  const a = make(h1)
  const t = new Node({ transport: true, rebroadcastDelay: 0.01 })
  t.addRoad(h1.road())
  t.addRoad(h2.road())
  const b = make(h2)
  const box = inbox(b)
  await withNodes([a, t, b], async () => {
    await a.announce()
    await until(() => hasPath(b, a))
    await a.send(b.address, 'found you', { timeout: 5 })
    await until(() => box.length)
  })
  assert.equal(box[0].content, 'found you')
})

test('fragmentation on a small-MTU road', async () => {
  const hub = new MemoryHub()
  const a = make(hub, { mtu: 255 })
  const b = make(hub, { mtu: 255 })
  const box = inbox(b)
  await withNodes([a, b], async () => {
    await a.announce()
    await b.announce()
    await until(() => hasPath(a, b) && hasPath(b, a))
    await a.send(b.address, 'x'.repeat(2000), { fields: new Map([['attachment', new Uint8Array(3000)]]) })
    await until(() => box.length)
  })
  assert.equal(box[0].content, 'x'.repeat(2000))
  assert.ok(hub.frames > 20)
})

test('several recipients', async () => {
  const hub = new MemoryHub()
  const [a, b, c, d] = [make(hub), make(hub), make(hub), make(hub)]
  const boxes = [inbox(b), inbox(c), inbox(d)]
  await withNodes([a, b, c, d], async () => {
    for (const n of [a, b, c]) await n.announce()
    await until(() => hasPath(a, b) && hasPath(a, c))
    const sent = await a.send([b.address, c.address], 'group hello')
    await until(() => boxes[0].length && boxes[1].length)
    await sleep(50)
    for (const box of boxes.slice(0, 2)) {
      assert.equal(box[0].content, 'group hello')
      assert.ok(equal(box[0].id, sent.id))
    }
    assert.equal(boxes[2].length, 0)
  })
})

test('propagation node stores and forwards', async () => {
  const hub = new MemoryHub()
  const a = make(hub)
  const b = make(hub)
  const prop = new Node({ propagate: true, rebroadcastDelay: 0.01 })
  prop.addRoad(hub.road())
  const box = inbox(b)
  await a.start()
  await b.start()
  await a.announce()
  await b.announce()
  await until(() => a.peerRatchet(b.address) && hasPath(b, a))
  await b.stop()
  await prop.start()
  await a.send(b.address, 'while you were away')
  await until(() => prop.store.has(b.address))
  await b.start()
  await b.announce()
  await until(() => box.length)
  assert.equal(box[0].content, 'while you were away')
  assert.ok(box[0].ratchetId)
  for (const n of [a, b, prop]) await n.stop()
})

test('links: handshake, messages both ways, resources, close', async () => {
  const hub = new MemoryHub()
  const a = make(hub)
  const b = make(hub)
  const boxA = inbox(a)
  const boxB = inbox(b)
  const got = []
  b.onResource((r) => got.push(r))
  await withNodes([a, b], async () => {
    await a.announce()
    await b.announce()
    await until(() => hasPath(a, b) && hasPath(b, a))
    const keys = await a.openLink(b.address)
    await until(() => b.linkTo(a.address))
    assert.ok(equal(b.linkTo(a.address).linkId, keys.linkId))
    const m = await a.send(b.address, 'on the link')
    assert.ok(m.recipients && equal(m.recipients[0], b.address))
    await until(() => boxB.length)
    assert.ok(boxB[0].linkId)
    await b.send(a.address, 'and back')
    await until(() => boxA.length)
    assert.equal(boxA[0].content, 'and back')
    assert.equal(await a.delivered(m, 5), true)
    const data = new Uint8Array(5000).map((_, i) => i * 7)
    assert.equal(await a.sendResource(b.address, data, { meta: 'blob', timeout: 10 }), true)
    assert.equal(got.length, 1)
    assert.ok(equal(got[0].data, data))
    assert.equal(got[0].meta, 'blob')
    await a.closeLink(b.address)
    await until(() => !b.linkTo(a.address))
  })
})

for (const mode of ['mac', 'encrypt']) {
  test(`road auth (${mode}) keeps outsiders out`, async () => {
    const hub = new MemoryHub()
    const auth = RoadAuth.fromPassphrase('secret', mode)
    const a = make(hub, { auth })
    const b = make(hub, { auth })
    const eve = make(hub, { auth: RoadAuth.fromPassphrase('wrong', mode) })
    const box = inbox(b)
    await withNodes([a, b, eve], async () => {
      for (const n of [a, b, eve]) await n.announce()
      await until(() => hasPath(a, b) && hasPath(b, a))
      await sleep(50)
      assert.ok(!hasPath(a, eve) && !hasPath(eve, a))
      await a.send(b.address, 'members only')
      await until(() => box.length)
    })
  })
}

test('quantumSafeOnly is the default and refuses prequantum peers', async () => {
  assert.throws(() => new Node({ identity: Identity.generate('prequantum') }))
  const hub = new MemoryHub()
  const a = make(hub)
  const old = make(hub, { suite: 'prequantum' })
  await withNodes([a, old], async () => {
    await old.announce()
    await a.announce()
    await until(() => hasPath(old, a))
    await sleep(50)
    assert.ok(!hasPath(a, old))
  })
})

test('unknown sender is looked up by keyset request', async () => {
  const hub = new MemoryHub()
  const a = make(hub)
  const b = make(hub)
  const box = inbox(b)
  await withNodes([a, b], async () => {
    await a.announce()
    await b.announce()
    await until(() => hasPath(a, b) && hasPath(b, a))
    b.identities.delete(toHex(a.address)) // b forgot a (restart)
    await a.send(b.address, 'remember me?')
    await until(() => box.length)
  })
})
