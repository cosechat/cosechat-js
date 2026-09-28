// Assemble the web example as a static site (for GitHub Pages): the page,
// the library it imports from src/, and the .js files of the packages its
// import map points at. Everything is addressed relative to the page, so the
// site works under any path (e.g. https://cosechat.github.io/cosechat-js/).
//
//   node scripts/build-web.js [outdir]      (default: _site)

import { cpSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const out = join(root, process.argv[2] || '_site')
const PACKAGES = ['@noble/hashes', '@noble/curves', '@noble/ciphers', '@noble/post-quantum', 'cborg']

rmSync(out, { recursive: true, force: true })
mkdirSync(out, { recursive: true })
cpSync(join(root, 'examples/web'), out, { recursive: true })
cpSync(join(root, 'src'), join(out, 'src'), { recursive: true })

// only the runtime modules of each package (no sources, types or tests)
function copyJs(from, to) {
  for (const name of readdirSync(from)) {
    const f = join(from, name)
    if (statSync(f).isDirectory()) {
      if (name !== 'node_modules' && name !== 'test' && name !== 'src') copyJs(f, join(to, name))
    } else if (name.endsWith('.js')) {
      mkdirSync(dirname(join(to, name)), { recursive: true })
      cpSync(f, join(to, name))
    }
  }
}
for (const p of PACKAGES) copyJs(join(root, 'node_modules', p), join(out, 'node_modules', p))

// serve files as they are (no Jekyll processing)
writeFileSync(join(out, '.nojekyll'), '')
console.log(`web site in ${out}`)
