#!/usr/bin/env node
// Shard DSP — agent context persistence hello world.
//
// Full loop:
//   Session 1 — create a context blob, upload it, store the magnet.
//   Session 2 — restore the context from the stored magnet.
//
// Requires : Node.js 14+, shard-gui running on localhost:9201.
// Dependencies : built-in modules only (http, fs, os, path).

const http = require('http')
const fs   = require('fs')
const os   = require('os')
const path = require('path')

const HOST        = '127.0.0.1'
const PORT        = 9201
const MAGNET_FILE = path.join(os.homedir(), '.shard_hello_magnet')

function post(endpoint, body, contentType) {
  return new Promise((resolve, reject) => {
    const opts = { host: HOST, port: PORT, path: endpoint, method: 'POST',
                   headers: { 'Content-Type': contentType,
                              'Content-Length': Buffer.byteLength(body) } }
    const req = http.request(opts, res => {
      const chunks = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => {
        const data = JSON.parse(Buffer.concat(chunks).toString())
        res.statusCode >= 400
          ? reject(new Error(data.error || `HTTP ${res.statusCode}`))
          : resolve(data)
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

function uploadFile(filePath) {
  const B    = 'shardbound'
  const name = path.basename(filePath)
  const body = Buffer.concat([
    Buffer.from(`--${B}\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\nContent-Type: application/octet-stream\r\n\r\n`),
    fs.readFileSync(filePath),
    Buffer.from(`\r\n--${B}--\r\n`),
  ])
  return post('/api/files/upload', body, `multipart/form-data; boundary=${B}`)
}

;(async () => {
  if (!fs.existsSync(MAGNET_FILE)) {
    // ── Session 1: save context ─────────────────────────────────────────────
    const ctx = { agent: 'hello-world', step: 1, memory: ['first run'] }
    const tmp = path.join(os.tmpdir(), 'shard_ctx.json')
    fs.writeFileSync(tmp, JSON.stringify(ctx, null, 2))

    console.log('Uploading context…')
    const { magnet } = await uploadFile(tmp)
    fs.writeFileSync(MAGNET_FILE, magnet)
    fs.unlinkSync(tmp)

    console.log('[OK] Context saved.\nMagnet:', magnet)
    console.log('Run again to restore it.')
  } else {
    // ── Session 2: restore context ──────────────────────────────────────────
    const magnet = fs.readFileSync(MAGNET_FILE, 'utf8').trim()
    console.log('Restoring context…\n' + magnet)

    const { path: restored } = await post(
      '/api/files/download',
      JSON.stringify({ magnet }),
      'application/json'
    )
    const data = JSON.parse(fs.readFileSync(restored, 'utf8'))
    console.log('[OK] Context restored:', data)
    fs.unlinkSync(MAGNET_FILE)
    console.log('Magnet file removed — next run starts fresh.')
  }
})().catch(e => { console.error('[error]', e.message); process.exit(1) })
