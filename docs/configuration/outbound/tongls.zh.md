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
  "tag": "tongls-out",
  "server": "proxy.example.com",
  "server_port": 443,
  "password": "REPLACE_WITH_GENERATED_PASSWORD",
  "path": "/",
  "handshake_timeout": "10s",
  "header_padding_min": 128,
  "header_padding_max": 512,
  "idle_session_check_interval": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 0,
  "client_metadata": "",
  "tls": {
    "enabled": true,
    "server_name": "proxy.example.com"
  }
}
```

示例密码是占位符。使用 `sing-box generate rand --base64 32` 生成独立的高强度密码，
并在两端配置匹配的值。

### 字段

#### server / server_port

==必填==

Tongls 服务端地址和端口。

#### password

==必填==

与服务端用户匹配的密码，同时用于 TLS 会话绑定的 HTTPS 升级认证和内层会话认证。
外层 HTTP 请求头发送认证证明，不直接发送密码。

#### path

升级路径，默认 `/`，必须与服务端一致。使用不超过 2,048 字节的绝对转义路径，不含查询或片段。
路径不是认证秘密。

#### handshake_timeout

TCP／TLS 建立及 HTTP 升级的截止时间，默认 `10s`。零值使用默认值，不接受负数。
每个新会话增加一次 HTTP 升级请求／响应，已有会话复用可分摊此成本。

#### header_padding_min / header_padding_max

外层 HTTP `Padding` 请求头值的字节长度区间，包含两端。
两者同时为零时使用默认 128–512；其他情况要求 `0 <= min <= max <= 4096`。
字符使用密码学随机源和 URL 安全 ASCII 字符集。长度不包含字段名和 HTTP 格式开销，
不指定 TLS 记录或 TCP 报文边界。此机制独立于内层填充，不会主动增加调度延迟。

#### initial_padding_scheme

可选的填充方案行数组，在首次已认证服务端设置交换前生效。
默认将上游方案的 `0=30-30` 改为 `0=16-256`，使认证明文从固定 64 字节变为 50–289 字节。
这些是应用层长度，不是网络报文大小。服务端仍可通过设置交换替换方案；
若要在后续会话保持同一策略，应配置匹配的服务端 `padding_scheme`。显式方案按客户端独立复制。

校验限制文本最多 16 KiB、`stop` 为 0–1024、每记录最多 64 个区间／检查条目。
认证记录 `0` 必须为一个正数区间且上界能用 uint16 表示；其他区间必须为正数、顺序正确，
每记录的区间最大值之和不超过 1 MiB。重复键、未知键及超出 `stop` 的记录会被拒绝。
单独配置 `stop=0` 可关闭初始内层填充策略。

#### idle_session_check_interval / idle_session_timeout / min_idle_session

继承的会话池控制：默认每 `30s` 检查空闲会话，默认清理空闲超过 `30s` 的会话，
并至少保留 `min_idle_session` 个空闲会话（默认零）。这些选项不会关闭 HTTPS 认证入口。

#### client_metadata

在已认证的内层 AnyTLS 会话中发送的可选元数据，默认为空。
背景参阅 [AnyTLS 客户端元数据](/zh/manual/misc/anytls-client-metadata/)。

#### tls

==必填==

参阅[出站 TLS](/zh/configuration/shared/tls/#出站)。Tongls 强制标准 Go TLS 1.3，
并验证证书链和主机名。私有 CA 可通过 `certificate` 或 `certificate_path` 配置。
不支持 `insecure`、`disable_sni`、仅指纹验证、uTLS、REALITY、kTLS、分片或 spoof。
ALPN 为 `http/1.1`；如显式配置列表，只接受该单一值。

### 拨号字段

参阅[拨号字段](/zh/configuration/shared/dial/)。不支持 TCP fast open。
