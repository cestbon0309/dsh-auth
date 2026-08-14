import { createHash, timingSafeEqual } from 'node:crypto'
import { createServer, request as httpRequest } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { connect } from 'node:net'
import type { Socket } from 'node:net'
import { networkInterfaces } from 'node:os'
import { Service } from '@deepseek-ai/cordis'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'

/**
 * @deepseek-ai/dsh-auth-gateway — an auth-gated reverse proxy that fronts the
 * DSH web GUI on all interfaces (IPv4 + IPv6).
 *
 * The shipped DSH web server deliberately refuses non-loopback binds and ships
 * no auth layer. This plugin keeps the internal server on loopback and stands a
 * second listener in front of it that:
 *   - binds `0.0.0.0` and/or `::` (dual-stack) so the GUI is reachable from the
 *     LAN / other hosts,
 *   - authenticates every HTTP request and WebSocket upgrade (HTTP Basic and/or
 *     a static Bearer token),
 *   - transparently proxies authorized traffic to the loopback server, rewriting
 *     the Host header so the backend's own trust fence still passes.
 */

/** Hop-by-hop headers a proxy must not blindly forward (RFC 7230 §6.1). */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

export interface AuthGatewayConfig {
  /** Front listen host: `0.0.0.0` (IPv4 all), `::` (IPv6, dual-stack by default), or a specific IP. */
  host?: string
  /** Front listen port. */
  port?: number
  /** Internal DSH webserver host the front proxies to (loopback default). */
  backendHost?: string
  /** When `host` is an IPv6 literal, disable dual-stack (IPv6-only). */
  ipv6Only?: boolean
  /** Run without any configured credentials (auth disabled) — insecure, opt-in. */
  allowWithoutAuth?: boolean
  /** Pathnames served without auth (static, non-sensitive files browsers fetch credential-less). */
  publicPaths?: string[]
  auth?: {
    /** Basic-auth username (empty disables basic auth). */
    username?: string
    /** Basic-auth password (empty disables basic auth). */
    password?: string
    /** Static bearer token, also accepted as `?token=` for WebSocket/SSE. */
    token?: string
    /** Challenge realm shown in the browser prompt. */
    realm?: string
  }
}

export const Config = z.object({
  host: z.string().default('::'),
  port: z.natural().max(65535).default(3081),
  backendHost: z.string().default('127.0.0.1'),
  ipv6Only: z.boolean().default(false),
  allowWithoutAuth: z.boolean().default(false),
  publicPaths: z.array(z.string()).default(['/manifest.webmanifest', '/favicon.ico']),
  auth: z.object({
    username: z.string().default(''),
    password: z.string().default(''),
    token: z.string().default(''),
    realm: z.string().default('dsh'),
  }).default({ username: '', password: '', token: '', realm: 'dsh' }),
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

/** Parse `Authorization: Basic …` into `{ user, pass }`, or null. */
function parseBasic(header: string | undefined): { user: string; pass: string } | null {
  if (typeof header !== 'string') return null
  const match = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header)
  if (!match) return null
  try {
    const decoded = Buffer.from(match[1], 'base64').toString('utf8')
    const at = decoded.indexOf(':')
    if (at < 0) return null
    return { user: decoded.slice(0, at), pass: decoded.slice(at + 1) }
  } catch {
    return null
  }
}

/**
 * Inline script polyfilling `crypto.randomUUID` for non-secure (plain-HTTP LAN)
 * contexts. Browsers expose it only in secure contexts (HTTPS / localhost), so
 * a plain-HTTP LAN visit otherwise breaks the client RPC/connection layer.
 */
const RANDOM_UUID_POLYFILL = `<script>/* dsh-auth-gateway: polyfill crypto.randomUUID for non-secure HTTP contexts */
(function(){if(typeof crypto.randomUUID==="function")return;crypto.randomUUID=function(){var b=new Uint8Array(16);crypto.getRandomValues(b);b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;var h="";for(var i=0;i<16;i++)h+=b[i].toString(16).padStart(2,"0");return h.slice(0,8)+"-"+h.slice(8,12)+"-"+h.slice(12,16)+"-"+h.slice(16,20)+"-"+h.slice(20);};})();</script>`

/**
 * Inject the polyfill as early as possible in the SPA shell so the client
 * bundles (deferred module scripts) run after it.
 */
function injectRandomUuidPolyfill(html: string): string {
  const head = /<head\b[^>]*>/i.exec(html)
  if (head) {
    const at = head.index + head[0].length
    return html.slice(0, at) + RANDOM_UUID_POLYFILL + html.slice(at)
  }
  const body = /<body\b[^>]*>/i.exec(html)
  if (body) return html.slice(0, body.index) + RANDOM_UUID_POLYFILL + html.slice(body.index)
  return RANDOM_UUID_POLYFILL + html
}

export default class AuthGateway extends Service {
  /** The backend webserver must exist (and be listening) before we front it. */
  static readonly inject = ['webServer']
  static Config = Config

  config: AuthGatewayConfig

  private front: Server | null = null
  private backendHost = '127.0.0.1'
  private backendPort = 3080

  private username = ''
  private password = ''
  private token = ''
  private realm = 'dsh'
  private basicEnabled = false
  private tokenEnabled = false
  private publicPaths: string[] = ['/manifest.webmanifest', '/favicon.ico']

  constructor(ctx: Context, config: AuthGatewayConfig) {
    super(ctx, 'auth-gateway')
    this.config = config
  }

  async [Service.init](): Promise<void> {
    const auth = this.config.auth ?? {}
    this.username = (auth.username ?? '').trim() || process.env.DSH_AUTH_USERNAME || ''
    this.password = auth.password ?? process.env.DSH_AUTH_PASSWORD ?? ''
    this.token = (auth.token ?? '').trim() || process.env.DSH_AUTH_TOKEN || ''
    this.realm = (auth.realm || 'dsh').replace(/"/g, '')
    this.basicEnabled = this.username !== '' && this.password !== ''
    this.tokenEnabled = this.token !== ''
    this.publicPaths = this.config.publicPaths ?? ['/manifest.webmanifest', '/favicon.ico']

    if (!this.basicEnabled && !this.tokenEnabled && !this.config.allowWithoutAuth) {
      throw new Error(
        'dsh-auth-gateway: no credentials configured. Set auth.username+auth.password (HTTP Basic), ' +
        'auth.token (Bearer), the DSH_AUTH_* environment variables, or allowWithoutAuth: true to run without auth.',
      )
    }

    this.backendHost = this.config.backendHost || '127.0.0.1'
    const webServer = (this.ctx as Context & {
      webServer?: {
        port?: number
        tapIndex?: (transform: (html: string) => string) => () => void
      }
    }).webServer
    if (typeof webServer?.port !== 'number') {
      throw new Error('dsh-auth-gateway: webServer service has no listening port')
    }
    this.backendPort = webServer.port

    // Patch the SPA shell so it works over plain HTTP from LAN clients, where
    // `crypto.randomUUID` is unavailable (secure-context-only API). Call the
    // method ON the service object — capturing it unbound loses `this`.
    if (typeof webServer.tapIndex === 'function') {
      this.ctx.effect(() => webServer.tapIndex!(injectRandomUuidPolyfill), 'dsh-auth-gateway: crypto.randomUUID polyfill')
    }

    const server = createServer((req, res) => this.handleRequest(req, res))
    server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket as Socket, head))
    server.on('error', (err) => this.ctx.logger.warn(err))
    await this.listen(server)

    this.front = server
    this.ctx.effect(() => () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections()
        server.close(() => resolve())
      }),
      'dsh-auth-gateway: front server',
    )

    if (!this.basicEnabled && !this.tokenEnabled) {
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
      // Dual-stack `::` is the single-socket v4+v6 answer; if this host has no
      // IPv6 stack at all, fall back to the v4 all-interfaces literal.
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

  /** Whether one request (HTTP or upgrade) carries acceptable credentials. */
  private authorized(req: IncomingMessage): boolean {
    const header = req.headers.authorization
    if (this.tokenEnabled) {
      if (typeof header === 'string' && header.startsWith('Bearer ')) {
        if (safeEqual(header.slice(7).trim(), this.token)) return true
      }
      try {
        const qToken = new URL(req.url ?? '/', 'http://dsh.internal').searchParams.get('token')
        if (qToken !== null && safeEqual(qToken, this.token)) return true
      } catch {
        /* malformed URL can't carry a valid token */
      }
    }
    if (this.basicEnabled) {
      const cred = parseBasic(header)
      if (cred && safeEqual(cred.user, this.username) && safeEqual(cred.pass, this.password)) return true
    }
    return false
  }

  /** The `WWW-Authenticate` value advertising every enabled scheme. */
  private challenge(): string {
    const parts: string[] = []
    if (this.basicEnabled) parts.push(`Basic realm="${this.realm}"`)
    if (this.tokenEnabled) parts.push(`Bearer realm="${this.realm}"`)
    return parts.join(', ')
  }

  /** Paths exempt from auth (browsers fetch manifest/favicon without credentials). */
  private isPublicPath(req: IncomingMessage): boolean {
    let pathname: string
    try {
      pathname = new URL(req.url ?? '/', 'http://dsh.internal').pathname
    } catch {
      return false
    }
    return this.publicPaths.includes(pathname)
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    if (!this.isPublicPath(req) && !this.authorized(req)) {
      res.writeHead(401, {
        'content-type': 'text/plain; charset=utf-8',
        'www-authenticate': this.challenge(),
        connection: 'close',
      })
      res.end('authentication required\n')
      return
    }
    this.proxyRequest(req, res)
  }

  private proxyRequest(req: IncomingMessage, res: ServerResponse): void {
    // Headers named by the request's own `Connection` header are hop-by-hop too.
    const connectionTokens = new Set<string>()
    const connHeader = req.headers.connection
    if (typeof connHeader === 'string') {
      for (const token of connHeader.split(',')) connectionTokens.add(token.trim().toLowerCase())
    }

    const headers: Record<string, string | string[] | undefined> = {}
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined) continue
      const lower = name.toLowerCase()
      // Host and Origin are rewritten to the loopback backend so its trust
      // fence sees a coherent same-origin loopback request (an un-rewritten
      // Origin would 403 because origin.host !== host.host).
      if (lower === 'host' || lower === 'origin') continue
      if (HOP_BY_HOP.has(lower) || connectionTokens.has(lower)) continue
      headers[name] = value
    }
    headers.host = `${this.backendHost}:${this.backendPort}`
    if (typeof req.headers.origin === 'string') {
      headers.origin = `http://${this.backendHost}:${this.backendPort}`
    }

    const proxyReq = httpRequest(
      {
        host: this.backendHost,
        port: this.backendPort,
        method: req.method,
        path: req.url,
        headers,
      },
      (proxyRes) => {
        const resHeaders: Record<string, string | string[] | undefined> = {}
        for (const [name, value] of Object.entries(proxyRes.headers)) {
          if (value === undefined) continue
          if (HOP_BY_HOP.has(name.toLowerCase())) continue
          resHeaders[name] = value
        }
        res.writeHead(proxyRes.statusCode ?? 502, resHeaders)
        proxyRes.pipe(res)
      },
    )

    proxyReq.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      }
      res.end(`bad gateway: ${err.message}\n`)
    })

    req.pipe(proxyReq)
    res.on('close', () => {
      if (!res.writableEnded) proxyReq.destroy()
    })
  }

  private handleUpgrade(req: IncomingMessage, socket: Socket, head: Buffer): void {
    if (!this.authorized(req)) {
      socket.end([
        'HTTP/1.1 401 Unauthorized',
        `WWW-Authenticate: ${this.challenge()}`,
        'Connection: close',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'authentication required',
      ].join('\r\n'))
      return
    }

    const backend = connect(this.backendPort, this.backendHost)
    backend.on('error', () => socket.destroy())
    backend.once('connect', () => {
      // Replay the upgrade as a transparent relay, rewriting Host and Origin to
      // the loopback backend so its trust fence sees loopback.
      const lines: string[] = [`${req.method} ${req.url} HTTP/${req.httpVersion}`]
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const headerName = req.rawHeaders[i]
        const headerValue = req.rawHeaders[i + 1]
        const lower = headerName.toLowerCase()
        if (lower === 'host' || lower === 'origin') continue
        lines.push(`${headerName}: ${headerValue}`)
      }
      lines.push(`Host: ${this.backendHost}:${this.backendPort}`)
      lines.push(`Origin: http://${this.backendHost}:${this.backendPort}`)
      lines.push('', '')
      backend.write(lines.join('\r\n'))
      if (head && head.length > 0) backend.write(head)
      socket.pipe(backend).pipe(socket)
    })
    socket.on('error', () => backend.destroy())
    socket.once('close', () => backend.destroy())
    backend.once('close', () => socket.destroy())
  }

  private printUrl(server: Server): void {
    const addr = server.address()
    const port = addr && typeof addr === 'object' ? addr.port : this.config.port ?? 3081
    const modes = this.basicEnabled && this.tokenEnabled
      ? 'basic+bearer'
      : this.basicEnabled ? 'basic' : this.tokenEnabled ? 'bearer' : 'none'
    const lan = lanAddresses()
    const target = lan.length > 0 ? lan[0] : this.config.host || '::'
    console.log(`dsh-auth-gateway: http://${target}:${String(port)} (all interfaces, auth: ${modes})`)
    if (lan.length > 1) {
      for (const extra of lan.slice(1)) console.log(`dsh-auth-gateway:   http://${extra}:${String(port)}`)
    }
  }
}
