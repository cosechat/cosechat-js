// RNode road: LoRa through an RNode (https://unsigned.io/rnode) on a serial
// port, speaking the RNode KISS host protocol (a port of the Python
// reference's roads/rnode.py, itself from Reticulum's RNodeInterface).
//
//   new RNodeRoad('/dev/ttyUSB0', { frequency: 868e6 })         Node (serialport package)
//   new RNodeRoad(await navigator.serial.requestPort(), {...})  browsers (Web Serial)
//   new RNodeRoad(port, {...})                                  any { write, onData, close }
//
// The radio carries up to 508 bytes per frame; Node fragments anything bigger.
// The road's bitrate comes from the radio settings, so the announce budget applies.

import * as kiss from './kiss.js'
import { Road } from './road.js'
import { nodeSerial, webSerial } from './serial.js'

export const CMD_DATA = 0x00
export const CMD_FREQUENCY = 0x01
export const CMD_BANDWIDTH = 0x02
export const CMD_TXPOWER = 0x03
export const CMD_SF = 0x04
export const CMD_CR = 0x05
export const CMD_RADIO_STATE = 0x06
export const CMD_RADIO_LOCK = 0x07
export const CMD_DETECT = 0x08
export const CMD_LEAVE = 0x0a
export const CMD_ST_ALOCK = 0x0b
export const CMD_LT_ALOCK = 0x0c
export const CMD_READY = 0x0f
export const CMD_STAT_RX = 0x21
export const CMD_STAT_TX = 0x22
export const CMD_STAT_RSSI = 0x23
export const CMD_STAT_SNR = 0x24
export const CMD_PLATFORM = 0x48
export const CMD_MCU = 0x49
export const CMD_FW_VERSION = 0x50
export const CMD_RESET = 0x55
export const CMD_ERROR = 0x90

export const DETECT_REQ = 0x73
export const DETECT_RESP = 0x46
export const RADIO_STATE_OFF = 0x00
export const RADIO_STATE_ON = 0x01

export const ERRORS = {
  0x01: 'radio initialisation failed',
  0x02: 'transmit failed',
  0x03: 'EEPROM locked',
  0x04: 'queue full',
  0x05: 'memory low',
  0x06: 'modem timeout'
}

export const RSSI_OFFSET = 157
export const REQUIRED_FIRMWARE = [1, 52]
export const HW_MTU = 508

const u32 = (v) => new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff])
const readU32 = (d) => ((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3]
const sleep = (s) => new Promise((resolve) => setTimeout(resolve, s * 1000))

export class RNodeError extends Error {
  constructor(message) {
    super(message)
    this.name = 'RNodeError'
  }
}

export class RNodeRoad extends Road {
  static MTU = HW_MTU

  constructor(port, { frequency, bandwidth = 125000, txpower = 7, sf = 8, cr = 5, stAlock = null, ltAlock = null, flowControl = false, baudRate = 115200, bootDelay = 2, timeout = 5, name = null } = {}) {
    super({ name: name || `rnode:${typeof port === 'string' ? port : 'custom'}`, mtu: HW_MTU })
    if (!(frequency >= 137e6 && frequency <= 3e9)) throw new RangeError('frequency out of range')
    if (!(bandwidth >= 7800 && bandwidth <= 1625000)) throw new RangeError('bandwidth out of range')
    if (!(sf >= 5 && sf <= 12) || !(cr >= 5 && cr <= 8) || !(txpower >= 0 && txpower <= 37)) throw new RangeError('sf, cr or txpower out of range')
    this.port = port
    this.config = { frequency, bandwidth, txpower, sf, cr }
    // LoRa air bitrate (same formula as Reticulum), for the announce budget
    this.bitrate = sf * (4 / cr / (2 ** sf / (bandwidth / 1000))) * 1000
    this.stAlock = stAlock
    this.ltAlock = ltAlock
    this.flowControl = flowControl
    this.baudRate = baudRate
    this.bootDelay = bootDelay
    this.timeout = timeout

    this.serial = null
    this.detected = false
    this.firmware = null
    this.platform = null
    this.mcu = null
    this.reported = {}
    this.radioState = null
    this.rssi = null
    this.snr = null
    this.errors = []

    this._decoder = new kiss.Decoder(HW_MTU * 2 + 8)
    this._waiters = []
    this._ready = true
    this._queue = []
  }

  // --- lifecycle ---

  async _open() {
    const p = this.port
    if (typeof p === 'string') return nodeSerial(p, { baudRate: this.baudRate })
    if (p && typeof p.open === 'function' && 'readable' in p) return webSerial(p, { baudRate: this.baudRate })
    return p
  }

  async start() {
    this.serial = await this._open()
    this.serial.onData = (d) => this._onBytes(d)
    if (this.bootDelay) await sleep(this.bootDelay)
    await this._write(new Uint8Array([kiss.FEND, CMD_DETECT, DETECT_REQ, kiss.FEND, CMD_FW_VERSION, 0x00, kiss.FEND, CMD_PLATFORM, 0x00, kiss.FEND, CMD_MCU, 0x00, kiss.FEND]))
    await this._wait(() => this.detected && this.firmware, 'device did not answer detect')
    const [maj, min] = this.firmware
    if (maj < REQUIRED_FIRMWARE[0] || (maj === REQUIRED_FIRMWARE[0] && min < REQUIRED_FIRMWARE[1])) throw new RNodeError(`firmware ${maj}.${min} too old, need ${REQUIRED_FIRMWARE.join('.')}`)
    const c = this.config
    await this._command(CMD_FREQUENCY, u32(c.frequency))
    await this._command(CMD_BANDWIDTH, u32(c.bandwidth))
    await this._command(CMD_TXPOWER, new Uint8Array([c.txpower]))
    await this._command(CMD_SF, new Uint8Array([c.sf]))
    await this._command(CMD_CR, new Uint8Array([c.cr]))
    const u16 = (v) => new Uint8Array([(v >> 8) & 0xff, v & 0xff])
    if (this.stAlock != null) await this._command(CMD_ST_ALOCK, u16(Math.round(this.stAlock * 100)))
    if (this.ltAlock != null) await this._command(CMD_LT_ALOCK, u16(Math.round(this.ltAlock * 100)))
    await this._command(CMD_RADIO_STATE, new Uint8Array([RADIO_STATE_ON]))
    const same = () => Object.keys(c).every((k) => this.reported[k] === c[k])
    await this._wait(() => this.radioState === RADIO_STATE_ON && same(), 'radio did not confirm configuration')
    await super.start()
  }

  async stop() {
    await super.stop()
    if (!this.serial) return
    try {
      await this._write(kiss.frame(CMD_LEAVE, new Uint8Array([0xff])))
    } catch {}
    // close what we opened (a device path, a Web Serial port), not a caller's own port object
    if (this.serial !== this.port) {
      try {
        await this.serial.close()
      } catch {}
    }
    this.serial = null
  }

  // --- io ---

  async send(frame) {
    if (frame.length > HW_MTU) throw new Error(`${this}: frame of ${frame.length} bytes exceeds ${HW_MTU}`)
    if (this.flowControl && !this._ready) {
      this._queue.push(frame)
      return
    }
    if (this.flowControl) this._ready = false
    await this._write(kiss.frame(CMD_DATA, frame))
  }

  _command(cmd, data) {
    return this._write(kiss.frame(cmd, data))
  }

  async _write(data) {
    if (!this.serial) throw new RNodeError(`${this}: not open`)
    await this.serial.write(data)
  }

  // resolve once cond() holds, re-checked whenever the device says something
  _wait(cond, err) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._waiters = this._waiters.filter((w) => w !== check)
        reject(new RNodeError(`${this}: ${err}`))
      }, this.timeout * 1000)
      const check = () => {
        if (this.errors.length) {
          clearTimeout(timer)
          reject(new RNodeError(this.errors[this.errors.length - 1]))
          return true
        }
        if (cond()) {
          clearTimeout(timer)
          resolve()
          return true
        }
        return false
      }
      if (!check()) this._waiters.push(check)
    })
  }

  _onBytes(data) {
    for (const [cmd, body] of this._decoder.feed(data)) this._onCommand(cmd, body)
    this._waiters = this._waiters.filter((check) => !check())
  }

  _onCommand(cmd, d) {
    if (cmd === CMD_DATA) {
      if (d.length) this._deliver(d)
    } else if (cmd === CMD_DETECT) this.detected = d[0] === DETECT_RESP
    else if (cmd === CMD_FW_VERSION && d.length >= 2) this.firmware = [d[0], d[1]]
    else if (cmd === CMD_PLATFORM && d.length) this.platform = d[0]
    else if (cmd === CMD_MCU && d.length) this.mcu = d[0]
    else if (cmd === CMD_FREQUENCY && d.length >= 4) this.reported.frequency = readU32(d)
    else if (cmd === CMD_BANDWIDTH && d.length >= 4) this.reported.bandwidth = readU32(d)
    else if (cmd === CMD_TXPOWER && d.length) this.reported.txpower = d[0]
    else if (cmd === CMD_SF && d.length) this.reported.sf = d[0]
    else if (cmd === CMD_CR && d.length) this.reported.cr = d[0]
    else if (cmd === CMD_RADIO_STATE && d.length) this.radioState = d[0]
    else if (cmd === CMD_STAT_RSSI && d.length) this.rssi = d[0] - RSSI_OFFSET
    else if (cmd === CMD_STAT_SNR && d.length) this.snr = ((d[0] << 24) >> 24) * 0.25
    else if (cmd === CMD_READY) {
      this._ready = true
      if (this._queue.length) this.send(this._queue.shift()).catch(() => {})
    } else if (cmd === CMD_ERROR && d.length) {
      const err = ERRORS[d[0]] || `hardware error 0x${d[0].toString(16).padStart(2, '0')}`
      console.error(`${this}: ${err}`)
      this.errors.push(err)
    } else if (cmd === CMD_RESET && d[0] === 0xf8 && this.online) {
      console.error(`${this}: device reset while online`)
      this.online = false
    }
  }
}
