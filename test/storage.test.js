// examples/storage.js: policy, encryption at rest, and file compatibility
// with the Python reference's examples/storage.py (when ../cosechat-py is here).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { FileRatchets, FileStore, loadIdentity, readPrivate, ratchetsFor, writePrivate } from '../examples/storage.js'
import { equal, toHex } from '../src/bytes.js'

const dir = () => mkdtempSync(join(tmpdir(), 'cosechat-storage-'))
const PY = new URL('../../cosechat-py/', import.meta.url).pathname
const PYTHON = join(PY, '.venv/bin/python')
const havePython = existsSync(PYTHON)

test('identity files: plain and locked, mode 0600', () => {
  const d = dir()
  const a = loadIdentity(join(d, 'plain'))
  assert.equal(statSync(join(d, 'plain')).mode & 0o777, 0o600)
  assert.ok(equal(loadIdentity(join(d, 'plain')).address, a.address))
  const b = loadIdentity(join(d, 'locked'), { passphrase: 'pw' })
  assert.throws(() => loadIdentity(join(d, 'locked')), /passphrase is needed/)
  assert.throws(() => loadIdentity(join(d, 'locked'), { passphrase: 'nope' }), /wrong passphrase/)
  assert.ok(equal(loadIdentity(join(d, 'locked'), { passphrase: 'pw' }).address, b.address))
})

test('ratchet policy: rotate when due, delete when expired, persist', () => {
  const d = dir()
  let now = 1000
  const ident = loadIdentity(join(d, 'id'))
  const r = ratchetsFor(join(d, 'id'), ident, { rotateEvery: 10, keepFor: 30, clock: () => now })
  const first = r.current()
  assert.equal(r.maintain(), false)
  now += 10
  assert.equal(r.maintain(), true)
  assert.equal(r.size, 2)
  assert.ok(r.get(first.kid))
  now += 25 // first is 35 s old: gone
  r.maintain()
  assert.equal(r.get(first.kid), null)
  const again = new FileRatchets(ident.kemAlg, join(d, 'id.ratchets'), { clock: () => now })
  assert.deepEqual(
    again.keys().map((k) => toHex(k.kid)),
    r.keys().map((k) => toHex(k.kid))
  )
})

test('file store keeps packets per destination, oldest first', () => {
  let now = 100
  const s = new FileStore(dir(), { perDest: 2, keepFor: 50, clock: () => now })
  const dest = new Uint8Array(16).fill(7)
  assert.ok(s.put(dest, 1, new Uint8Array([1])))
  now += 1
  assert.ok(s.put(dest, 4, new Uint8Array([2])))
  assert.equal(s.put(dest, 1, new Uint8Array([3])), false)
  assert.ok(s.has(dest))
  const got = s.take(dest)
  assert.deepEqual(
    got.map(([k]) => k),
    [1, 4]
  )
  assert.equal(s.has(dest), false)
})

test('Python reads our locked identity, and we read its locked ratchets', { skip: !havePython && 'no ../cosechat-py/.venv' }, () => {
  const d = dir()
  const ours = loadIdentity(join(d, 'js-id'), { passphrase: 'shared secret' })
  const script = `
import sys
sys.path.insert(0, ${JSON.stringify(join(PY, 'examples'))})
from pathlib import Path
import storage
from cosechat import Identity
p = Path(${JSON.stringify(d)})
ident = storage.load_identity(p / 'js-id', passphrase='shared secret', create=False)
print(ident.address.hex())
py = storage.load_identity(p / 'py-id', passphrase='shared secret')
r = storage.ratchets_for(p / 'py-id', py, passphrase='shared secret')
r.current()
print(py.address.hex(), r.current().kid.hex())
`
  const [jsAddr, pyLine] = execFileSync(PYTHON, ['-c', script], { encoding: 'utf8' }).trim().split('\n')
  assert.equal(jsAddr, toHex(ours.address))
  const [pyAddr, rid] = pyLine.split(' ')
  const py = loadIdentity(join(d, 'py-id'), { passphrase: 'shared secret', create: false })
  assert.equal(toHex(py.address), pyAddr)
  const r = ratchetsFor(join(d, 'py-id'), py, { passphrase: 'shared secret' })
  assert.equal(toHex(r.current().kid), rid)
  assert.ok(readFileSync(join(d, 'py-id')).length > 0)
  assert.throws(() => readPrivate(join(d, 'py-id')), /passphrase is needed/)
  writePrivate(join(d, 'x'), new Uint8Array([1, 2, 3]))
})
