import type { Bytes } from './bytes.js'
export const LORA_MTU: 508
export function frames(packet: Bytes, mtu?: number): number
export function measure(suite: string): Record<string, number | Bytes>
/** the Markdown table `cosechat sizes` prints */
export function table(): string
