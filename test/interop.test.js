// Two-way conformance with the Python reference, when it is checked out next
// to this repo (../cosechat-py with its .venv): skipped otherwise.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { check, generate } from '../src/vectors.js'
import { table } from '../src/sizes.js'

const PY = new URL('../../cosechat-py/', import.meta.url).pathname
const CLI = join(PY, '.venv/bin/cosechat')
const havePython = existsSync(CLI)

test('generated vectors pass our own checker', () => {
  assert.deepEqual(check(generate()), [])
})

test('generated vectors pass the Python checker', { skip: !havePython && 'no ../cosechat-py/.venv' }, () => {
  const file = join(mkdtempSync(join(tmpdir(), 'cosechat-')), 'js-vectors.json')
  writeFileSync(file, JSON.stringify(generate()))
  const out = execFileSync(CLI, ['check', file], { encoding: 'utf8' })
  assert.match(out, /^ok$/m)
})

test('sizes match the table in SPEC.md', { skip: !existsSync(join(PY, 'SPEC.md')) && 'no ../cosechat-py/SPEC.md' }, () => {
  const spec = readFileSync(join(PY, 'SPEC.md'), 'utf8')
  const embedded = spec.split('<!-- sizes -->')[1].split('<!-- /sizes -->')[0].trim()
  assert.equal(table(), embedded)
})
