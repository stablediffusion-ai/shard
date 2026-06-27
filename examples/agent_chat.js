#!/usr/bin/env node
// Shard DSP — agent chat hello world.
// Join a room, send a message, listen for responses via WebSocket.
//
// Requires : Node.js 14+, shard-gui on localhost:9201. Built-ins only.
// Usage    : node agent_chat.js <room> <message>

const http = require('http'), net = require('net'), crypto = require('crypto')
const HOST = '127.0.0.1', PORT = 9201
const room = process.argv[2] || 'general'
const msg  = process.argv[3] || 'hello from agent'

function post(path, body) {
  const data = JSON.stringify(body)
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: HOST, port: PORT, path, method: 'POST',
        headers: { 'Content-Type': 'application/json',
                   'Content-Length': Buffer.byteLength(data) } },
      res => { const c = []; res.on('data', d => c.push(d))
               res.on('end', () => resolve(JSON.parse(Buffer.concat(c).toString()))) }
    )
    req.on('error', reject); req.end(data)
  })
}

function wsListen(ms = 8000) {
  return new Promise(resolve => {
    const key  = crypto.randomBytes(16).toString('base64')
    const sock = net.createConnection(PORT, HOST)
    sock.write(`GET /ws HTTP/1.1\r\nHost: ${HOST}:${PORT}\r\nUpgrade: websocket\r\n` +
               `Connection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`)
    let done = false, buf = Buffer.alloc(0)
    sock.on('data', chunk => {
      buf = Buffer.concat([buf, chunk])
      if (!done) { const i = buf.indexOf('\r\n\r\n'); if (i < 0) return; done = true; buf = buf.slice(i + 4) }
      while (buf.length >= 2) {
        let len = buf[1] & 0x7F, off = 2
        if (len === 126) { if (buf.length < 4) break; len = buf.readUInt16BE(2); off = 4 }
        if (buf.length < off + len) break
        try {
          const e = JSON.parse(buf.slice(off, off + len).toString())
          if (e.type === 'ChatMessage') {
            const p = e.payload
            console.log(`[${p.room}] <${p.sender.slice(0, 12)}…>: ${p.content}`)
          }
        } catch (_) {}
        buf = buf.slice(off + len)
      }
    })
    sock.on('error', () => {})
    setTimeout(() => { sock.destroy(); resolve() }, ms)
  })
}

;(async () => {
  console.log(`Joining #${room}…`)
  await post('/api/chat/join', { room })
  console.log(`Sending: ${JSON.stringify(msg)}`)
  await post('/api/chat/send', { content: msg })
  console.log('[OK] Message sent. Listening for responses (8 s)…\n')
  await wsListen(8000)
  console.log('\nDone.')
})().catch(e => { console.error('[error]', e.message); process.exit(1) })
