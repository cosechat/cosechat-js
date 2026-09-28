// Serial ports for the RNode road, behind one small interface:
//
//   { write(bytes): Promise, onData: (bytes) => void, close(): Promise }
//
//   nodeSerial(path, { baudRate })   Node, needs the `serialport` package
//   webSerial(port, { baudRate })    browsers (Chrome/Edge), a SerialPort from
//                                    navigator.serial.requestPort()

export async function nodeSerial(path, { baudRate = 115200 } = {}) {
  let SerialPort
  try {
    ;({ SerialPort } = await import('serialport'))
  } catch {
    throw new Error('the RNode road in Node needs the serialport package: npm install serialport')
  }
  const sp = new SerialPort({ path, baudRate, autoOpen: false })
  await new Promise((resolve, reject) => sp.open((e) => (e ? reject(e) : resolve())))
  const port = {
    onData: null,
    write: (bytes) => new Promise((resolve, reject) => sp.write(Buffer.from(bytes), (e) => (e ? reject(e) : sp.drain(() => resolve())))),
    close: () => new Promise((resolve) => (sp.isOpen ? sp.close(() => resolve()) : resolve()))
  }
  sp.on('data', (d) => port.onData && port.onData(new Uint8Array(d)))
  return port
}

export async function webSerial(serialPort, { baudRate = 115200 } = {}) {
  await serialPort.open({ baudRate })
  const writer = serialPort.writable.getWriter()
  let reader = null
  let open = true
  const port = {
    onData: null,
    write: (bytes) => writer.write(bytes),
    async close() {
      open = false
      try {
        await reader?.cancel()
      } catch {}
      writer.releaseLock()
      await serialPort.close()
    }
  }
  ;(async () => {
    while (open && serialPort.readable) {
      reader = serialPort.readable.getReader()
      try {
        while (true) {
          const { value, done } = await reader.read()
          if (done) break
          if (value && port.onData) port.onData(value)
        }
      } catch {
        // a read error (e.g. unplugged): try again while still open
      } finally {
        reader.releaseLock()
      }
    }
  })()
  return port
}
