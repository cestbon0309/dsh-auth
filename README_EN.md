# dsh-auth-gateway

An authenticated, VPN-style TCP tunnel gateway for reaching the DeepSeek Harness web GUI from remote devices as if local.

[中文](README.md) · Apache-2.0

## What

DSH's browser client only enables its full surface (settings plane, file open, `crypto.randomUUID`) when the URL is loopback, so an HTTP reverse proxy cannot make a LAN URL behave. This plugin is instead a **raw TCP tunnel gateway**:

- internal DSH stays on `127.0.0.1:3080` (default, untouched);
- the plugin listens on `0.0.0.0` / `::` (dual-stack), authenticates each inbound connection with a token, then relays the byte stream to the loopback server;
- a tiny `tunnel.mjs` script on the remote device maps `localhost:<port>` to the gateway;
- the browser URL stays `localhost`, so DSH treats the session as local — everything works natively.

## Config

| Field | Default | Meaning |
| --- | --- | --- |
| `host` | `::` | gateway listen address (`0.0.0.0` / `::` / specific IP) |
| `port` | `3081` | gateway (tunnel) port |
| `backendHost` | `127.0.0.1` | internal DSH address |
| `auth.token` | `''` | tunnel token (preferred) |
| `auth.password` | `''` | tunnel token fallback |
| `allowWithoutAuth` | `false` | allow running without a token (insecure) |

Token resolution: `auth.token`, then `auth.password`, then `DSH_AUTH_TOKEN`. With none configured (and `allowWithoutAuth` false), startup fails closed.

## Build

```bash
pnpm install && pnpm build
```

## Install

```bash
dsh plugin --profile web add "link:<absolute-path>/dsh-auth-gateway"
```

Add a row to `$DSH_HOME/profiles/web/cordis.patch.yml`:

```yaml
- insert:
    - id: auth-gateway
      name: dsh-auth-gateway
      config:
        host: '::'
        port: 3081
        auth:
          token: 'your-token'
```

Run `dsh web`.

## Usage (remote device)

```bash
node tunnel.mjs <host-lan-ip> 3081 <token> 3080
# e.g. node tunnel.mjs 192.168.50.93 3081 my-token 3080
```

Then open `http://localhost:3080`. Keep the tunnel running in the background or as a service.

## Note

- The tunnel authenticates but does not encrypt; for public networks use SSH port-forwarding or a VPN/TLS.
- The gateway relays only to `127.0.0.1:<internal-port>`, never to arbitrary hosts.

## License

[Apache-2.0](./LICENSE)
