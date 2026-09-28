import { readFileSync } from 'node:fs'
import { fromHex } from '../src/bytes.js'

export const vectors = JSON.parse(readFileSync(new URL('./vectors/vectors.json', import.meta.url)))
export const h = (s) => fromHex(s)
