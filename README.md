# dsh-auth-gateway

给 DeepSeek Harness 的 Web GUI 加「鉴权 + 监听所有地址（IPv4+IPv6）」的前置网关插件。

[English](README_EN.md) · Apache-2.0

## 是什么

DSH 出厂只监听 `127.0.0.1`，且没有任何鉴权。本插件保持内部服务器仍监听 loopback，在前面再起一个**带鉴权的网关**，监听 `0.0.0.0` / `::`（双栈），认证通过后透传到内部（含 WebSocket）。

## 配置

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `host` | `::` | 前置监听地址（`0.0.0.0` / `::` / 具体 IP） |
| `port` | `3081` | 前置端口（内部 DSH 仍在 `3080`） |
| `auth.username` | `''` | Basic 用户名 |
| `auth.password` | `''` | Basic 密码 |
| `auth.token` | `''` | Bearer token（也支持 `?token=`） |

Basic 与 Bearer 可叠加，任一通过即可；都未配置则启动时**失败关闭**。也支持环境变量 `DSH_AUTH_USERNAME` / `DSH_AUTH_PASSWORD` / `DSH_AUTH_TOKEN`。

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
          username: dsh
          password: '你的强密码'
```

启动 `dsh web`，浏览器打开 `http://<机器IP>:3081`。

## 使用

```bash
curl -u dsh:密码 http://<机器IP>:3081/
curl -H 'Authorization: Bearer <token>' http://<机器IP>:3081/
```

## 说明

仅 HTTP 层鉴权，无 TLS；跨公网请前置 nginx/Caddy 做 HTTPS。

## 许可

[Apache-2.0](./LICENSE)
