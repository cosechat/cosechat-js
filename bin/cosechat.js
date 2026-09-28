#!/usr/bin/env node
// cosechat developer tool (the same commands as the Python reference's `cosechat`).
//
//   cosechat keygen [--suite pq|hybrid|prequantum] -o FILE   new identity (plain COSE_KeySet)
//   cosechat info FILE                                        describe an identity
//   cosechat address ADDRESS                                  hex <-> address text
//   cosechat vectors [-o FILE]                                write interop test vectors
//   cosechat check FILE                                       verify vectors from any implementation
//   cosechat sizes                                            measured wire sizes (Markdown)
//
// Running a node, and how its keys are stored, is up to the application: see
// examples/echo-bot.js and examples/storage.js.

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { parseArgs } from 'node:util'
import { toHex } from '../src/bytes.js'
import { decode } from '../src/cbor.js'
import { addressText, parseAddress } from '../src/contact.js'
import { Identity, SUITES } from '../src/identity.js'
import { getAlg } from '../src/keys.js'

const USAGE = `usage: cosechat <command>

  keygen [--suite pq|hybrid|prequantum] -o FILE [--force]   new identity (plain COSE_KeySet)
  info FILE                                                  describe an identity
  address ADDRESS                                            hex <-> address text
  vectors [-o FILE]                                          write interop test vectors
  check FILE                                                 verify vectors from any implementation
  sizes                                                      measured wire sizes (Markdown)`

function die(msg) {
  console.error(msg)
  process.exit(1)
}

const [cmd, ...rest] = process.argv.slice(2)
const { values: o, positionals: args } = parseArgs({
  args: rest,
  allowPositionals: true,
  options: {
    suite: { type: 'string', default: 'pq' },
    output: { type: 'string', short: 'o' },
    force: { type: 'boolean' },
    help: { type: 'boolean', short: 'h' }
  }
})

const commands = {
  keygen() {
    if (!o.output) die('keygen needs -o FILE')
    if (!SUITES[o.suite]) die(`unknown suite ${o.suite} (${Object.keys(SUITES).join(', ')})`)
    if (existsSync(o.output) && !o.force) die(`${o.output} exists (use --force to replace it)`)
    const ident = Identity.generate(o.suite)
    writeFileSync(o.output, ident.toBytes(true), { mode: 0o600 })
    console.log(toHex(ident.address))
  },

  info() {
    const file = args[0] || die('info needs a FILE')
    const raw = new Uint8Array(readFileSync(file))
    let obj = null
    try {
      obj = decode(raw)
    } catch {}
    if (Array.isArray(obj) && typeof obj[0] === 'string') die(`${file}: encrypted at rest (${obj[0]})`)
    let ident
    try {
      ident = Identity.fromBytes(raw)
    } catch (e) {
      die(`${file}: not a plain identity keyset (${e.message})`)
    }
    const row = (k, v) => console.log(k.padEnd(14) + v)
    row('address', toHex(ident.address))
    row('address text', addressText(ident.address))
    for (const k of ident.signKeys) row('sign', `${k.algorithm.name} (${k.pub.length} byte public key)`)
    row('ratchet KEM', `${getAlg(ident.kemAlg).name} (announced, not part of the keyset)`)
    row('keyset', `${ident.publicBytes.length} bytes public`)
    row('private', ident.hasPrivate ? 'yes' : 'no')
    row('quantum-safe', ident.quantumSafe ? 'yes' : 'no')
  },

  address() {
    const a = parseAddress(args[0] || die('address needs an ADDRESS'))
    console.log(`${toHex(a)}\n${addressText(a)}`)
  },

  async vectors() {
    const { generate } = await import('../src/vectors.js')
    const data = JSON.stringify(generate(), null, 1)
    if (o.output) writeFileSync(o.output, data)
    else console.log(data)
  },

  async check() {
    const { check } = await import('../src/vectors.js')
    const fails = check(JSON.parse(readFileSync(args[0] || die('check needs a FILE'), 'utf8')))
    for (const f of fails) console.log('FAIL', f)
    console.log(fails.length ? `${fails.length} failures` : 'ok')
    process.exit(fails.length ? 1 : 0)
  },

  async sizes() {
    const { table } = await import('../src/sizes.js')
    console.log(table())
  }
}

if (!cmd || o.help || !commands[cmd]) die(USAGE)
try {
  await commands[cmd]()
} catch (e) {
  die(`cosechat ${cmd}: ${e.message}`)
}
