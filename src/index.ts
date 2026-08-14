import { createServer as createTcpServer, connect } from 'node:net'
import type { Server, Socket } from 'node:net'
import { createHash, timingSafeEqual } from 'node:crypto'
import { networkInterfaces } from 'node:os'
import { Service } from '@deepseek-ai/cordis'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'

/**
 * @deepseek-ai/dsh-auth-gateway — an authenticated TCP tunnel gateway (VPN-like)
 * that lets remote devices reach the DeepSeek Harness web GUI exactly as if they
 * were on the host's loopback.
 *
 * The DSH web client only enables its full surface (settings plane, file open,
 * crypto.randomUUID) when the browser URL is loopback, so an HTTP reverse proxy
 * cannot make a LAN URL behave. Instead this plugin stands a raw TCP gateway:
 * a client opens a tunnel (see `tunnel.mjs`), authenticates with a token, and
 * the gateway relays the raw stream to the loopback DSH server. The remote
 * browser then browses `http://localhost:<port>` and DSH sees a local client.
 */

export interface AuthGatewayConfig {
  /** Gateway listen host: `0.0.0.0` (IPv4 all), `::` (IPv6, dual-stack by default), or a specific IP. */
  host?: string
  /** Gateway listen port (the tunnel endpoint). */
  port?: number
  /** Internal DSH webserver host the tunnel relays to (loopback default). */
  backendHost?: string
  /** When `host` is an IPv6 literal, disable dual-stack (IPv6-only). */
  ipv6Only?: boolean
  /** Run without a token (auth disabled) — insecure, opt-in. */
  allowWithoutAuth?: boolean
  auth?: {
    /** Tunnel token (preferred; falls back to `auth.password`). */
    token?: string
    /** Fallback tunnel token when `auth.token` is empty. */
    password?: string
    /** Legacy (unused): kept so an old `auth.username` field still validates. */
    username?: string
    /** Legacy (unused): kept so an old `auth.realm` field still validates. */
    realm?: string
  }
}

export const Config = z.object({
  host: z.string().default('::'),
  port: z.natural().max(65535).default(3081),
  backendHost: z.string().default('127.0.0.1'),
  ipv6Only: z.boolean().default(false),
  allowWithoutAuth: z.boolean().default(false),
  auth: z.object({
    token: z.string().default(''),
    password: z.string().default(''),
    username: z.string().default(''),
    realm: z.string().default('dsh'),
  }).default({ token: '', password: '', username: '', realm: 'dsh' }),
})

/** Non-internal IPv4/IPv6 literals, for the startup URL line. */
function lanAddresses(): string[] {
  const out: string[] = []
  for (const list of Object.values(networkInterfaces())) {
    for (const iface of list ?? []) {
      if (!iface || iface.internal) continue
      const family = String(iface.family)
      if (family === '4' || family === 'IPv4') out.push(iface.address)
      else if ((family === '6' || family === 'IPv6') && !iface.address.startsWith('fe80:')) out.push(`[${iface.address}]`)
    }
  }
  return out
}

/** Constant-time string equality (hash-normalized so lengths never leak). */
function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a, 'utf8').digest()
  const hb = createHash('sha256').update(b, 'utf8').digest()
  return timingSafeEqual(ha, hb)
}

const HANDSHAKE_MAX_BYTES = 1024
const HANDSHAKE_TIMEOUT_MS = 10000

export default class AuthGateway extends Service {
  /** The backend webserver must exist (and be listening) before we relay to it. */
  static readonly inject = ['webServer']
  static Config = Config

  config: AuthGatewayConfig

  private gateway: Server | null = null
  private backendHost = '127.0.0.1'
  private backendPort = 3080
  private token = ''

  constructor(ctx: Context, config: AuthGatewayConfig) {
    super(ctx, 'auth-gateway')
    this.config = config
  }

  async [Service.init](): Promise<void> {
    const auth = this.config.auth ?? {}
    this.token = (auth.token ?? '').trim() || (auth.password ?? '').trim() || process.env.DSH_AUTH_TOKEN || ''
    if (this.token === '' && !this.config.allowWithoutAuth) {
      throw new Error(
        'dsh-auth-gateway: no tunnel token configured. Set auth.token (or auth.password), ' +
        'the DSH_AUTH_TOKEN environment variable, or allowWithoutAuth: true to run without auth.',
      )
    }

    this.backendHost = this.config.backendHost || '127.0.0.1'
    const webServer = (this.ctx as Context & { webServer?: { port?: number } }).webServer
    if (typeof webServer?.port !== 'number') {
      throw new Error('dsh-auth-gateway: webServer service has no listening port')
    }
    this.backendPort = webServer.port

    const server = createTcpServer((socket) => this.handleTunnel(socket))
    server.on('error', (err) => this.ctx.logger.warn(err))
    await this.listen(server)

    this.gateway = server
    this.ctx.effect(() => () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve())
      }),
      'dsh-auth-gateway: tunnel gateway',
    )

    if (this.token === '') {
      this.ctx.logger.warn('dsh-auth-gateway: authentication is DISABLED (allowWithoutAuth)')
    }
    this.printUrl(server)
  }

  private async listen(server: Server): Promise<void> {
    const host = this.config.host || '::'
    const port = this.config.port ?? 3081
    const ipv6Only = this.config.ipv6Only ?? false
    const isV6 = host.includes(':')

    const attempts: Array<{ host: string; ipv6Only?: boolean }> = []
    if (isV6) {
      attempts.push({ host, ipv6Only })
      if (!ipv6Only && host === '::') attempts.push({ host: '0.0.0.0' })
    } else {
      attempts.push({ host })
    }

    let lastError: unknown
    for (const attempt of attempts) {
      try {
        await new Promise<void>((resolve, reject) => {
          server.once('error', reject)
          const options = attempt.ipv6Only === undefined
            ? { port, host: attempt.host }
            : { port, host: attempt.host, ipv6Only: attempt.ipv6Only }
          server.listen(options, () => {
            server.off('error', reject)
            resolve()
          })
        })
        return
      } catch (err) {
        lastError = err
      }
    }
    throw lastError
  }

  /** Authenticate one inbound tunnel connection, then relay it to the backend. */
  private handleTunnel(client: Socket): void {
    let handshakeBuf = Buffer.alloc(0)
    let backend: Socket | null = null
    let backendReady = false
    let pending: Buffer[] = []
    const timeout = setTimeout(() => client.destroy(), HANDSHAKE_TIMEOUT_MS)

    client.on('data', (chunk: Buffer): void => {
      // Relay established: forward straight to the backend.
      if (backend) {
        if (backendReady) backend.write(chunk)
        else pending.push(chunk)
        return
      }

      // Handshake phase: read the first line (`TOKEN <token>\n`).
      handshakeBuf = Buffer.concat([handshakeBuf, chunk])
      const nl = handshakeBuf.indexOf(0x0a) // '\n'
      if (nl === -1) {
        if (handshakeBuf.length > HANDSHAKE_MAX_BYTES) client.destroy()
        return
      }
      clearTimeout(timeout)
      const line = handshakeBuf.slice(0, nl).toString('utf8').trim()
      const rest = handshakeBuf.slice(nl + 1)
      if (!this.authorized(line)) {
        client.destroy()
        return
      }

      backend = connect(this.backendPort, this.backendHost)
      backend.on('error', () => client.destroy())
      backend.on('data', (c: Buffer): void => { client.write(c) })
      backend.once('end', () => client.end())
      backend.once('connect', () => {
        backendReady = true
        if (rest.length > 0) backend!.write(rest)
        for (const c of pending) backend!.write(c)
        pending = []
      })
      client.on('error', () => backend!.destroy())
      client.once('end', () => backend!.end())
    })

    client.once('error', () => client.destroy())
  }

  /** Whether the handshake line carries the configured token. */
  private authorized(line: string): boolean {
    if (this.token === '') return true // allowWithoutAuth
    const match = /^TOKEN\s+(.+)$/i.exec(line)
    if (!match) return false
    return safeEqual(match[1], this.token)
  }

  private printUrl(server: Server): void {
    const addr = server.address()
    const port = addr && typeof addr === 'object' ? addr.port : this.config.port ?? 3081
    const lan = lanAddresses()
    const target = lan.length > 0 ? lan[0] : this.config.host || '::'
    console.log(`dsh-auth-gateway: tunnel gateway on ${target}:${String(port)} (auth: ${this.token === '' ? 'none' : 'token'})`)
    console.log(`  remote: node tunnel.mjs <host> ${String(port)} <token> <local-port>  ->  http://localhost:<local-port>`)
    if (lan.length > 1) {
      for (const extra of lan.slice(1)) console.log(`dsh-auth-gateway:   http://${extra}:${String(port)}`)
    }
  }
}
