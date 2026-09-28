export interface Vectors {
  description: string
  [section: string]: unknown
}
/** Fresh interop vectors from this implementation. */
export function generate(): Vectors
/** Verify a vector file from any implementation; returns the failures. */
export function check(vectors: Vectors): string[]
export function exact(): { name: string; inputs: Record<string, unknown>; expect: Record<string, unknown> }[]
