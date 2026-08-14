#!/usr/bin/env node
// dsh-auth-gateway tunnel client: relay localhost:<local-port> -> gateway -> DSH loopback.
//
// usage: node tunnel.mjs <gateway-host> <gateway-port> <token> <local-port>
//
// Then open http://localhost:<local-port> in the browser. The browser URL stays
// loopback, so DSH treats the session as local (full settings plane, no
// secure-context issues), and the gateway authenticates every connection.

import { createServer, connect } from 'node:net'

const [gatewayHost, gatewayPort, token, localPort] = process.argv.slice(2)
if (!gatewayHost || !gatewayPort || !token || !localPort || Number.isNaN(Number(gatewayPort)) || Number.isNaN(Number(localPort))) {
  console.error('usage: node tunnel.mjs <gateway-host> <gateway-port> <token> <local-port>')
  console.error('example: node tunnel.mjs 192.168.50.93 1206 my-token 3080')
  process.exit(1)
}

const gPort = Number(gatewayPort)
const lPort = Number(localPort)

const server = createServer((local) => {
  const upstream = connect(gPort, gatewayHost)
  upstream.on('error', () => local.destroy())
  upstream.once('connect', () => {
    upstream.write(`TOKEN ${token}\n`)
    local.on('data', (c) => upstream.write(c))
    upstream.on('data', (c) => local.write(c))
    local.once('end', () => upstream.end())
    upstream.once('end', () => local.end())
    local.once('close', () => upstream.destroy())
  })
  local.on('error', () => upstream.destroy())
})

server.listen(lPort, '127.0.0.1', () => {
  console.log(`tunnel ready: http://localhost:${lPort}  ->  ${gatewayHost}:${gPort}  ->  dsh`)
})
