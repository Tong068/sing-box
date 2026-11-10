---
icon: material/tunnel
---

Tongls 是基于 AnyTLS 改造的独立本地协议，配置类型为 `tongls`。
原版 `anytls` 的实现与配置保持独立，继续可用。
Tongls 始终使用经过认证的 HTTPS 升级入口，两端都必须支持 Tongls；
不兼容普通 AnyTLS 或此前的私有模式原型。
参阅[协议与部署指南](/zh/manual/proxy-protocol/tongls/)。

### 结构

```json
{
  "type": "tongls",
  "tag": "tongls-in",
  "listen": "::",
  "listen_port": 443,
  "users": [
    {
      "name": "client",
      "password": "REPLACE_WITH_GENERATED_PASSWORD"
    }
  ],
  "path": "/",
  "fallback": {
    "server": "127.0.0.1",
    "server_port": 8080
  },
  "handshake_timeout": "10s",
  "idle_timeout": "5m",
  "max_connections": 1024,
  "tls": {
    "enabled": true,
    "certificate_path": "/path/to/fullchain.pem",
    "key_path": "/path/to/private-key.pem"
  }
}
```

示例密码是占位符。使用 `sing-box generate rand --base64 32` 生成独立的高强度密码，
并在两端配置匹配的值。

### 字段

#### users

==必填==

接受 1–1,024 个用户，每个用户的 `name` 非空且唯一，`password` 也非空且唯一。
外层 HTTPS 与内层 AnyTLS 认证必须对应同一用户。额外握手不会提升弱密码的强度。

#### path

升级路径，默认 `/`，必须与客户端一致。使用不超过 2,048 字节的绝对转义路径，
不能包含查询或片段。路径不是秘密。

#### fallback

==必填==

固定的明文 HTTP 网站后端，由 `server` 与非零 `server_port` 指定。
TLS 在 Tongls 终止，不能填写 HTTPS 后端端口。建议使用本机网站，并设置网站自己的请求体与资源限制。

普通 HTTP/1.1、HTTP/2 请求和认证失败的升级请求通过同一个固定反向代理处理。
未认证请求无法指定代理目标。后端拨号不使用环境 HTTP 代理或普通代理路由规则。
反向代理的正常逐跳字段处理会移除 `Proxy-Authorization: Tongls ...`，
网站自身的 `Authorization` 认证仍然可用。畸形 HTTP 使用原生 HTTP 解析行为。

#### handshake_timeout

初始 TLS／HTTP 请求头截止时间及 HTTP 请求头读取超时；升级之后，收集内层认证前缀另有独立截止时间。
每阶段默认 `10s`。零值使用默认值，不接受负数。

#### idle_timeout

连接空闲超时，默认 `5m`，在加密套接字发生 I/O 时刷新。零值使用默认值，不接受负数。

#### max_connections

已接受连接的数量上限，包括 TLS 握手、网站连接和升级后的会话。
默认 `1024`，范围 1–65,536；零值使用默认值。这不是每会话内的流数量限制。
HTTP 服务的 `MaxHeaderBytes` 配置为 8,192，Go 解析器另有正常缓冲余量。

#### padding_scheme

可选的填充方案行数组，使用继承自 AnyTLS 的方案格式。
Tongls 默认将上游方案的 `0=30-30` 替换为 `0=16-256`；继承的采样不包含上界，
内层认证明文为 50–289 字节。这些数值不是 TLS 记录或 TCP 报文长度。
已认证的设置交换仍可更新客户端后续会话使用的方案。

显式方案采用与出站 [`initial_padding_scheme`](/zh/configuration/outbound/tongls/#initial_padding_scheme)
相同的严格校验限制。

#### tls

==必填==

证书选项参阅[入站 TLS](/zh/configuration/shared/tls/#入站)。
Tongls 要求标准证书 TLS 1.3，并真正提供 `h2` 和 `http/1.1` 服务。
如指定 `alpn`，只能包含这两个名称；监听器会启用两者。
不支持 `insecure`、REALITY、kTLS 或 TLS 客户端证书认证。

### 监听字段

参阅[监听字段](/zh/configuration/shared/listen/)。Tongls 必须使用自身的 HTTPS 监听器，
不支持入站 `detour` 或注入连接。物理传输为 TCP；内层 AnyTLS 会话复用和 UDP-over-TCP 保留。
