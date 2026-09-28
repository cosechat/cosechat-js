import type { Bytes } from '../bytes.js'

/** What the RNode road talks to. */
export interface SerialLike {
  write(bytes: Bytes): Promise<unknown> | unknown
  onData: ((bytes: Bytes) => void) | null
  close?(): Promise<unknown> | unknown
}

/** Node: needs the `serialport` package. */
export function nodeSerial(path: string, opts?: { baudRate?: number }): Promise<SerialLike>
/** Browsers: a SerialPort from navigator.serial.requestPort(). */
export function webSerial(port: unknown, opts?: { baudRate?: number }): Promise<SerialLike>
