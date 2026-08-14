# dsh-auth-gateway

An auth-gated reverse proxy that lets the DeepSeek Harness web GUI listen on all interfaces (IPv4 + IPv6).

[中文](README.md) · Apache-2.0

## What

Stock `dsh web` listens only on `127.0.0.1` with no auth. This plugin keeps the internal server on loopback and stands an auth-gated front on `0.0.0.0` / `::` (dual-stack), proxying authenticated traffic (including WebSockets).

## Config

| Field | Default | Meaning |
| --- | --- | --- |
| `host` | `::` | front listen address (`0.0.0.0` / `::` / specific IP) |
| `port` | `3081` | front port (internal DSH stays on `3080`) |
| `auth.username` | `''` | basic username |
| `auth.password` | `''` | basic password |
| `auth.token` | `''` | bearer token (also `?token=`) |

Basic and Bearer combine — either passes. With neither configured, startup fails closed. Env fallbacks: `DSH_AUTH_USERNAME` / `DSH_AUTH_PASSWORD` / `DSH_AUTH_TOKEN`.

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
          username: dsh
          password: 'a strong password'
```

Run `dsh web`, open `http://<host-ip>:3081`.

## Usage

```bash
curl -u dsh:password http://<host-ip>:3081/
curl -H 'Authorization: Bearer <token>' http://<host-ip>:3081/
```

## Note

- Injects a `crypto.randomUUID` polyfill so the UI works over plain HTTP from LAN clients (non-secure context).
- HTTP-layer auth only, no TLS; front with nginx/Caddy for HTTPS on public exposure.

## License

[Apache-2.0](./LICENSE)
