---
icon: material/tunnel
---

# Tongls

Tongls 是基于 AnyTLS 改造的独立协议，配置类型为 `tongls`。
它在原有 AnyTLS 认证、数据帧和会话复用之前，增加真实 HTTPS 入口和与当前 TLS 会话绑定的认证。
原版 `anytls` 的实现与配置保持独立；选择 `tongls` 时始终启用 HTTPS 认证入口，不需要额外开关。
此本地协议不属于上游 AnyTLS，也不承诺不可识别。

```text
TCP → 验证服务端的 TLS 1.3 → 已认证 HTTP/1.1 Upgrade → AnyTLS 会话 → 流
                            普通 HTTP/1.1 或 HTTP/2 → 固定网站后端
```

Tongls 监听器不会将未认证的字节前缀直接视为 AnyTLS 登录。
请求由原生 Go HTTP 解析器处理，未满足升级认证条件的请求进入真实网站反向代理。
网站后端需要单独部署。

## 兼容性与边界

- 两端都必须使用支持 Tongls 的构建，并配置 `type: "tongls"`。
  Tongls 不兼容普通 AnyTLS 端点，也不兼容此前的 `anytls.private` 原型；不自动降级。
- 原有 `type: "anytls"` 继续使用原版实现和配置，无需迁移。
  Tongls 的内层核心分支有与锁定上游 AnyTLS 库双向互通的测试，但外层握手是独立协议。
- 内层 AnyTLS 协议、流处理、会话复用及原有 UDP-over-TCP 适配均保留，物理传输仍为 TCP。
- Tongls 要求使用自身 HTTPS 监听器，不支持入站 detour 或注入连接。
  TLS 必须在 Tongls 监听器终止：前置终止 TLS 的 CDN 或反向代理会改变 exporter，从而导致认证失败。
  不终止 TLS 的透明 TCP 转发不属于这种情况。
- 强制使用标准 Go TLS 1.3，并验证证书链和主机名；支持私有 CA。
  Tongls 不支持 uTLS、REALITY、kTLS、`insecure`、`disable_sni`、仅指纹验证、TLS 分片或 spoof，
  服务端也不会要求 TLS 客户端证书认证。

服务端真正提供 `h2` 和 `http/1.1`。Tongls 客户端使用 `http/1.1`，因为隧道入口采用 HTTP/1.1 Upgrade；
普通 HTTP/2 请求仍访问网站。这不等同于使用浏览器 TLS 协议栈。
Go TLS 行为、HTTP/1.1 使用方式、长度、时序、目标及连接复用仍可能被观察。
改变固定长度或提供一个网站，本身不能证明分类器或主动探测者无法识别服务。

目前两端都需要使用支持 Tongls 的修改版 sing-box。原版 Mihomo 客户端不支持 Tongls，在 Mihomo 中使用需要另行实现。

## 部署

使用自己控制的域名、有效证书和固定的明文 HTTP 网站后端。
示例后端为 `127.0.0.1:8080`，不能在该位置填写 HTTPS 端口。
网站仍需单独设置请求体和资源限制。

为每个用户生成独立的高强度密码：

```shell
sing-box generate rand --base64 32
```

替换两端的 `REPLACE_WITH_GENERATED_PASSWORD`、域名和证书路径。
HTTP 证明不是第二个独立认证因子，弱密码仍然是弱密码。
不要记录密码、TLS exporter 或认证证明。

### 服务端

```json
{
  "inbounds": [
    {
      "type": "tongls",
      "tag": "tongls-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "name": "tongls-client",
          "password": "REPLACE_WITH_GENERATED_PASSWORD"
        }
      ],
      "tls": {
        "enabled": true,
        "certificate_path": "/path/to/fullchain.pem",
        "key_path": "/path/to/private-key.pem"
      },
      "path": "/",
      "fallback": {
        "server": "127.0.0.1",
        "server_port": 8080
      },
      "handshake_timeout": "10s",
      "idle_timeout": "5m",
      "max_connections": 1024
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
```

### 客户端

```json
{
  "inbounds": [
    {
      "type": "mixed",
      "tag": "local",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "tongls",
      "tag": "tongls-out",
      "server": "proxy.example.com",
      "server_port": 443,
      "password": "REPLACE_WITH_GENERATED_PASSWORD",
      "tls": {
        "enabled": true,
        "server_name": "proxy.example.com"
      },
      "path": "/",
      "handshake_timeout": "10s",
      "header_padding_min": 128,
      "header_padding_max": 512
    }
  ],
  "route": {
    "final": "tongls-out"
  }
}
```

代理域名的 DNS 解析按普通 AnyTLS 部署方式配置。原有空闲会话选项仍可使用，
不会在每个流结束时强制重建会话。完整字段参阅[入站](/zh/configuration/inbound/tongls/)
和[出站](/zh/configuration/outbound/tongls/)。

网站回落始终使用管理员指定的 HTTP 后端，不使用请求提供的目标地址、普通代理路由规则或环境 HTTP 代理设置。
普通反向代理的逐跳字段处理会移除私有 `Proxy-Authorization: Tongls ...` 字段，
网站的 `Authorization` 不经特殊改写而保留。
畸形 HTTP 使用原生 HTTP 解析行为，不返回 AnyTLS 专属认证诊断。

## Tongls 握手 v1

客户端完成并验证 TLS 1.3 后，向配置路径发送无请求体的 HTTP/1.1 `GET`，包含：

- `Connection: Upgrade`
- `Upgrade: tongls-v1`
- `Proxy-Authorization: Tongls <规范标准 Base64 编码的令牌>`
- 随机长度和内容的 `Padding` 请求头值

路径是路由配置，不是秘密。必须是不超过 2,048 字节的绝对转义路径，不能带查询或片段，两端需要一致。
HTTP/2 或带请求体的请求不能进行私有升级。

令牌包含 16 字节凭证选择器和 32 字节请求证明，编码后为 64 个规范标准 Base64 字符。
使用以下确切输入：

```text
K = SHA256(密码字节)
selector = first16(HMAC-SHA256(K, "Tongls-v1 credential selector"))
E = TLS-Exporter("EXPORTER-Tongls-v1", 空上下文, 32 字节)
M = "Tongls-v1 request\x00" || E
    || len32be(method) || method || len32be(host) || host || len32be(uri) || uri
proof = HMAC-SHA256(K, M)
token = Base64(selector || proof)
```

`host` 为 HTTP Host 值，存在端口时包含端口；`uri` 为原始请求 URI；各长度字段以字节为单位。
服务端按选择器查找凭证，再使用 HMAC 比较验证完整请求证明。
未知选择器也使用随机占位密钥计算一次 HMAC，不会为每个配置用户分别计算 HMAC，
使这部分计算量不随用户数量放大。这不承诺字典查找为恒定时间，也不承诺所有请求的网络时序一致。
即使主机名和路径相同，将证明复制到另一条 TLS 连接也不能通过验证。
这个性质仅针对跨 TLS 连接复制证明，不隐藏流量特征，也不能保护已经泄露的密码。

成功时服务端返回 HTTP/1.1 `101 Switching Protocols` 及匹配的 Connection／Upgrade 字段。
两端保留已缓冲的后续字节。然后才进行原有 AnyTLS 密码哈希认证和填充前缀，
继续使用现有设置交换、数据流和会话生命周期。HTTP 证明不取代或重新定义 AnyTLS 数据帧协议。
服务端只有在 HTTP 认证通过后，才在新的截止时间内收集内层 34 字节认证头及其声明长度的填充。
这允许内层认证分段到达，同时不会让普通短 HTTP 请求等待 AnyTLS 所需的 32 字节前缀。

认证失败或未提供认证时，请求走网站路径，不返回私有认证错误或挑战。
无效、缺失或重复的证明字段不会进入 AnyTLS 解析器；HTTP 服务和网站仍可能返回正常的 HTTP 错误。

## 填充与成本

这里有两个相互独立的控制：

| 控制项 | 默认值与含义 |
| --- | --- |
| 外层 HTTP 请求头填充 | `Padding` 字段值为 128–512 个 ASCII 字节，包含区间两端，不含字段名和格式开销。长度及字符来自密码学随机源；最多可配置 4,096 字节。 |
| 初始内层 AnyTLS 方案 | 仅将上游默认方案中的 `0=30-30` 改成 `0=16-256`。继承的区间采样不含上界，得到 16–255 字节填充，即 50–289 字节认证明文。 |

外层填充上下界同时为零时使用默认值；其他情况要求 `0 <= min <= max <= 4096`。
实现不会主动增加调度延迟。
出站 `initial_padding_scheme` 在首次设置交换前选择每个客户端的初始方案；
已认证服务端下发的更新仍会替换它。配置匹配的服务端 `padding_scheme` 可在后续会话维持同一策略。

这些数值是明文写入／请求头值长度，不是 TCP 报文或 TLS 记录长度。
Tongls 默认方案移除了内层认证固定 64 字节这一条件，但同时增加了自己的 HTTP 请求／响应。
因此每个新会话额外需要一次 HTTP 升级往返及相应流量；复用 AnyTLS 会话可以分摊成本。
应分开测量冷启动和复用会话，不应只在对照协议中关闭复用。

## 资源限制与验证

Tongls 服务端默认初始 TLS／HTTP 请求头截止时间为 10 秒，连接空闲超时为 5 分钟，连接上限为 1,024。
上限包含未认证连接、网站连接和已接管的 AnyTLS 会话，不是每会话的流数量限制。
加密套接字上的活动刷新空闲截止时间；关闭服务端也会关闭已接管会话。
HTTP 升级成功后，内层 AnyTLS 认证前缀使用单独的 `handshake_timeout` 截止时间，默认也为 10 秒。

HTTP 服务将 `MaxHeaderBytes` 配置为 8,192，另有 Go 解析器正常的缓冲余量。
客户端为升级响应头解析设置 16 KiB 输入限制。这些数值不是总内存使用保证。
固定后端的拨号和响应头超时分别为 10 秒，并使用单独受限的空闲连接池；网站仍需要自己的应用限制。

无法运行报文驱动测试时，只运行相关包：

```shell
go test ./transport/tongls ./transport/tonglshttp ./protocol/tongls -count=1 -timeout=90s
go vet ./transport/tongls ./transport/tonglshttp ./protocol/tongls
go test ./transport/tongls -run '^$' -fuzz '^FuzzInitialPaddingScheme$' -fuzztime=10s
go test ./transport/tonglshttp -run '^$' -fuzz '^FuzzAuthorization$' -fuzztime=10s
go test ./transport/tonglshttp -run '^$' -fuzz '^FuzzPath$' -fuzztime=10s
go test ./protocol/tongls -run '^$' -bench '^BenchmarkTonglsCost$' -benchtime=100x -count=3 -timeout=90s
```

测试覆盖上游／本地内层协议互通、会话复用、正确私有升级、普通 HTTP/1.1 和 HTTP/2 网站请求、
错误／重放／篡改证明、缓冲字节保留、证书验证、截止时间／取消／连接限制及关闭行为。
网站对照使用同一固定后端，将特定请求的响应与普通反向代理比较；这不是对审查系统检测率的测量。

`BenchmarkTonglsCost` 在本机回环接口上，用 16 KiB 请求和响应比较原版 AnyTLS／Tongls。
两个冷启动场景都会在每次样本后清空会话池；两个热会话场景都在一次不计时的预热后保留复用。
它报告总耗时、内存分配、每次操作的 TLS 握手数量和首字节延迟分位数。
目标为进程内回显路由，不是真实远端应用。Windows 时钟可能无法分辨很短的热会话样本；
`unresolved-ttfb-fraction` 报告该比例，零值分位数会省略，不解释为零延迟。
此基准用于测量实现成本，不评价流量分类抵抗能力。

前后对照实验应固定网站、证书、TLS 实现、工作负载和网络路径。
分别测试 GET／HEAD、未知路径、完整错误证明、短／慢输入、非法 HTTP、提前关闭和 ALPN 变化，
记录响应字节、关闭方式、时序及资源占用；冷启动与复用会话分开比较。
实际 TLS 记录和报文大小应通过抓包观察，同时报告额外流量、p95 延迟和检测结果。

实现性质应准确表述为：未认证入口使用真实 HTTP 行为；定义的网站响应测试场景匹配其对照；
跨 TLS 连接复制证明会被拒绝；Tongls 移除了内层认证默认固定 64 字节的写入。
这些性质不代表已经完成公网抓包、受控丢包实验或审查分类器评估。
要证明检测率降低，应在代表性的独立测试流量上固定误报率后测量。

### 本地验收记录：2026 年 11 月 10 日

下表记录改名前的 AnyTLS 私有原型验证；更名后的专项回归用于核对相同能力。历史模糊测试计数不代表更名后再次执行。

Windows amd64、Go 1.25.5 下，专项测试、配置往返、JSON Schema、`go vet` 和命令行构建通过。
本轮仅运行指定测试包，不调用 WinDivert；未完成竞态检测、真实公网抓包或分类器检测率评估。

| 检查 | 观察到的结果 |
| --- | --- |
| 同一证书下发送普通 GET | 普通 AnyTLS 关闭连接、不返回 HTTP；Tongls 返回测试网站 HTTP 200，均未把未认证请求送到代理路由。 |
| 短 HTTP、畸形 HTTP、带错误证明的请求 | 指定测试的响应与相同后端的普通反向代理一致（比较时归一化 Date），未测量所有可能的响应时序。 |
| 复制认证证明到另一 TLS 会话，或修改 Host／路径 | 无法进入隧道，按普通 HTTP 请求处理。 |
| 外层用户与内层 AnyTLS 用户不一致 | 拒绝进入代理路由。 |
| 四个顺序代理流 | 只建立一次 TLS 连接，会话复用保留。 |
| 认证前缀分段、超时、服务关闭 | 合法分段正常工作；超时释放连接；服务关闭会终止已接管的会话。 |

三个各十秒的模糊测试分别完成 1,953,486 次初始填充输入、344,141 次认证输入和 314,644 次路径输入，无失败。
这些结果确认了上述具体行为，不能换算成对未知探测系统的成功率。

## 从此前私有原型迁移

普通 AnyTLS 用户不需要修改配置。仅迁移此前本地原型时：

1. 将两端的 `"type": "anytls"` 改为 `"type": "tongls"`。
2. 将原 `private` 对象内的 `path`、`fallback`、超时、连接数和请求头填充字段移至对应入站或出站的顶层。
3. 删除 `private` 对象及其 `enabled` 开关；保留 `tls.enabled`。
4. 两端同时升级。Tongls 的 HTTP 升级名称、认证方案和 TLS exporter 域均已更名，旧原型不能与之互通。

本页客户端和服务端示例已经采用新的扁平配置。原版 `anytls` 不接受这些 Tongls 扩展字段。
