// types/*.d.ts must declare exactly the values each module exports.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'

const root = new URL('..', import.meta.url)
const modules = [
  ...readdirSync(new URL('src/', root))
    .filter((f) => f.endsWith('.js'))
    .map((f) => f.slice(0, -3)),
  ...readdirSync(new URL('src/roads/', root)).map((f) => 'roads/' + f.slice(0, -3))
]

function declared(text) {
  const names = new Set()
  for (const m of text.matchAll(/^export (?:declare )?(?:function|class|const) (\w+)/gm)) names.add(m[1])
  for (const m of text.matchAll(/^export \{([^}]+)\} from/gm))
    for (const n of m[1].split(','))
      names.add(
        n
          .trim()
          .split(/\s+as\s+/)
          .pop()
      )
  for (const m of text.matchAll(/^export \* as (\w+) from/gm)) names.add(m[1])
  return names
}

for (const mod of modules) {
  test(`types/${mod}.d.ts matches src/${mod}.js`, async () => {
    const runtime = new Set(Object.keys(await import(new URL(`src/${mod}.js`, root))))
    const types = declared(readFileSync(new URL(`types/${mod}.d.ts`, root), 'utf8'))
    assert.deepEqual([...runtime].filter((n) => !types.has(n)).sort(), [], 'exported but not declared')
    assert.deepEqual([...types].filter((n) => !runtime.has(n)).sort(), [], 'declared but not exported')
  })
}
