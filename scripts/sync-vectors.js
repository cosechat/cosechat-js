// Copy the interop vectors from the Python reference (a sibling checkout).
import { copyFileSync, mkdirSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const src = process.argv[2] || new URL('../../cosechat-py/tests/vectors', import.meta.url).pathname
const dst = new URL('../test/vectors', import.meta.url).pathname
mkdirSync(dst, { recursive: true })
for (const f of readdirSync(src)) {
  copyFileSync(join(src, f), join(dst, f))
  console.log(f)
}
