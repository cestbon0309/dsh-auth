# dsh-auth-gateway

给 DeepSeek Harness 的 Web GUI 加一个「带鉴权的 VPN 式 TCP 隧道网关」，让远端设备像在主机本地一样访问。

[English](README_EN.md) · Apache-2.0

## 是什么

DSH 的浏览器客户端只在 `localhost`/`127.*` 下开放完整功能（设置面、打开文件、`crypto.randomUUID` 等），所以 HTTP 反向代理无法让内网 IP 表现得像本机。本插件改成**原始 TCP 隧道网关**：

- 内部 DSH 仍监听 `127.0.0.1:3080`（默认，不动）；
- 插件监听 `0.0.0.0` / `::`（双栈），每个入站连接先做**令牌鉴权**，通过后把字节流原样中继到内部 loopback；
- 远端设备跑一个极小的隧道脚本 `tunnel.mjs`，把本地 `localhost:<端口>` 透传到网关；
- 浏览器地址仍是 `localhost` → DSH 视为本机 → 所有功能原生可用，无需任何 patch。

## 配置

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `host` | `::` | 网关监听地址（`0.0.0.0` / `::` / 具体 IP） |
| `port` | `3081` | 网关（隧道）端口 |
| `backendHost` | `127.0.0.1` | 内部 DSH 地址 |
| `auth.token` | `''` | 隧道令牌（优先） |
| `auth.password` | `''` | 隧道令牌回退值 |
| `allowWithoutAuth` | `false` | 允许无令牌（不安全） |

令牌取 `auth.token`，其次 `auth.password`，再其次 `DSH_AUTH_TOKEN`。都未配置且未开 `allowWithoutAuth` 则启动报错（失败关闭）。

## 构建

```bash
pnpm install && pnpm build
```

## 安装

```bash
dsh plugin --profile web add "link:<绝对路径>/dsh-auth-gateway"
```

在 `$DSH_HOME/profiles/web/cordis.patch.yml` 新增一行：

```yaml
- insert:
    - id: auth-gateway
      name: dsh-auth-gateway
      config:
        host: '::'
        port: 3081
        auth:
          token: '你的令牌'
```

启动 `dsh web`。

## 使用（远端设备）

```bash
node tunnel.mjs <主机内网IP> 3081 <令牌> 3080
# 例如：node tunnel.mjs 192.168.50.93 3081 my-token 3080
```

然后浏览器打开 `http://localhost:3080`。隧道脚本也可以放在后台（`&`）或做成 systemd/计划任务常驻。

## 说明

- 隧道只做令牌鉴权、不加密；跨公网请走 SSH 端口转发或套 VPN/TLS。
- 网关只中继到 `127.0.0.1:<内部端口>`，不会变成开放代理。

## 许可

[Apache-2.0](./LICENSE)
