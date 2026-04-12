# NRUP

基于 nDTLS 的可靠加密 UDP 传输协议。通过 FEC 前向纠错与 ARQ 选择性重传的双重机制，在丢包时实现零延迟恢复，极端情况下通过重传保证可靠交付。为高丢包、高延迟的跨国链路和受限网络环境设计。

[English](README_EN.md)

## 概述

NRUP 在 UDP 之上构建了一套完整的可靠传输机制，同时保持 UDP 的低延迟特性。协议使用 nDTLS 加密层，线上流量与标准 DTLS 1.2 不可区分。

核心设计目标：
- **零延迟丢包恢复**：FEC 前向纠错即时恢复，ARQ 重传兜底，避免 TCP 的队头阻塞
- **自适应网络变化**：BBR 拥塞控制 + RTT 感知的 FEC 冗余调整
- **流量伪装**：AnyConnect 兼容的 DTLS 指纹，DPI 无法区分真实 VPN 和 NRUP
- **跨平台零依赖**：纯 Go 实现，支持 x86 / ARM / MIPS 交叉编译

## 架构

```
应用层
  ↓ Write(data)
会话层 (连接管理、迁移、有序交付)
  ↓
可靠层 ─┬─ FEC (Reed-Solomon 冗余编码, 即时恢复)
        └─ ARQ (选择性重传, 超时兜底)
  ↓
拥塞层 (BBR: Pacing + CWND + ProbeRTT)
  ↓
加密层 (nDTLS: AES-GCM / ChaCha20, X25519 握手)
  ↓
UDP
```

## 与 TCP / KCP / QUIC 的区别

|          | TCP    | KCP     | QUIC    | NRUP    |
|----------|--------|---------|---------|---------|
| 传输层    | TCP    | UDP     | UDP     | UDP     |
| 加密      | TLS    | 无      | TLS 1.3 | nDTLS   |
| 丢包恢复  | 重传    | 重传    | 重传     | FEC+ARQ |
| 拥塞控制  | CUBIC  | 自定义  | BBR     | BBR     |
| 队头阻塞  | 有     | 无      | 部分    | 无      |
| 连接迁移  | 无     | 无      | 有      | 有      |
| 代码量    | 内核级  | ~5K    | ~100K   | ~2.8K   |

**FEC + ARQ 双机制**：常规丢包（≤M个）由 FEC 冗余数据直接恢复，零额外延迟；极端丢包（>M个）自动触发 ARQ 重传兜底。在 200ms RTT 的跨国链路上，FEC 恢复 = 0ms，ARQ 重传 = 200ms，TCP 重传 = 200ms+。大多数场景走 FEC 快路径。

## 性能

| 指标 | 数值 | 说明 |
|------|------|------|
| nDTLS 吞吐 | 108,496 pps | 纯加密收发 |
| 端对端 | 4,089 pps | 含 FEC + BBR |
| FEC 编码 | 187 MB/s | Reed-Solomon SIMD 加速 |
| FEC 解码 | 36 MB/s | 含矩阵求逆 |
| AES-256-GCM | 330 MB/s | x86 AES-NI |
| ChaCha20 | 379 MB/s | 软件实现，ARM 友好 |
| BBR | 60ns/op | 零内存分配 |
| 每包开销 | 41 字节 | 13 header + 12 nonce + 16 tag |

## 使用

```go
import "github.com/nyarime/nrup"

// 服务端
listener, _ := nrup.Listen(":4000", nrup.DefaultConfig())
nrup, _ := listener.Accept()
defer conn.Close()

buf := make([]byte, 4096)
n, _ := conn.Read(buf)
conn.Write(buf[:n])

// 客户端
conn, _ := nrup.Dial("server:4000", nrup.DefaultConfig())
defer conn.Close()

conn.Write([]byte("hello"))
n, _ := conn.Read(buf)

// 连接统计
stats := conn.Stats()
fmt.Printf("RTT: %v, Loss: %.1f%%\n", stats.RTT, stats.LossRate*100)
```

## 配置

```go
cfg := &nrup.Config{
    FECData:      10,                    // 数据分片数
    FECParity:    3,                     // 冗余分片数（可恢复3个丢包）
    MaxBandwidthMbps: 100,                   // 非限速！仅告诉BBR线路大约多快，BBR会自动调整
    Cipher:       nrup.CipherAuto,       // 自动选择加密算法
    IdleTimeout:  120 * time.Second,     // 空闲超时
    StreamMode:   false,                 // false=数据报(FEC+BBR) true=流(直通)
}
```

## 加密算法

| 算法 | 适用场景 | 性能 |
|------|---------|------|
| `aes-256-gcm` | x86/ARM64 (硬件 AES-NI) | 330 MB/s |
| `chacha20-poly1305` | ARM/MIPS (无 AES 硬件) | 379 MB/s |
| `xchacha20-poly1305` | 需要扩展 nonce | 类似 ChaCha20 |
| `auto` (默认) | 自动检测 CPU | 始终最优 |

## API

| 方法 | 说明 |
|------|------|
| `Dial(addr, cfg)` | 连接服务端 |
| `Listen(addr, cfg)` | 监听端口 |
| `listener.Accept()` | 接受连接 |
| `conn.Read(buf)` | 接收数据 |
| `conn.Write(data)` | 发送数据 |
| `conn.Stats()` | 连接统计 |
| `conn.Migrate(addr)` | 连接迁移 |
| `conn.SessionID()` | 会话标识 |
| `conn.Close()` | 关闭连接 |
| `NewMux(conn)` | 创建多路复用器 |
| `mux.Open()` | 打开新Stream |
| `mux.Accept()` | 接受Stream |
| `stream.Read(buf)` | Stream读取 |
| `stream.Write(data)` | Stream写入 |
| `stream.Close()` | 关闭Stream |

## 许可证

Apache License 2.0

## 流量伪装

握手阶段完全模仿 Cisco AnyConnect VPN 的 DTLS 指纹：

```
ClientHello:
  Version:      DTLS 1.0 → 1.2
  Cipher Suites: ECDHE_RSA_AES_256_CBC_SHA (Cisco标准)
  Session ID:   32 bytes (承载 X25519 公钥)

ServerHello:
  Selected:     ECDHE_RSA_AES_256_CBC_SHA
  Session ID:   32 bytes (承载 X25519 公钥)

数据传输:
  ContentType:  23 (application_data)
  Version:      DTLS 1.2
  加密:         AES-256-GCM（实际使用，非 CBC）
```

DPI 检测结果：标准 AnyConnect VPN 连接。

## 安全模型

| 威胁 | 防护措施 |
|------|---------|
| 中间人攻击 (MITM) | PSK + HMAC 对等认证 |
| 重放攻击 | 64位滑动窗口 bitmap |
| 密钥泄露 | X25519 前向保密 (PFS)，每连接独立密钥 |
| 流量识别 | AnyConnect DTLS 指纹伪装 |
| 密钥派生弱点 | HKDF-Extract + Expand (RFC 5869) |
| 加密算法攻击 | AES-256-GCM / ChaCha20-Poly1305 (AEAD) |
| Nonce重用 | 每包独立 crypto/rand 随机 nonce |

### 已知限制

- 无证书/PKI体系，依赖PSK分发
- 单Listener同时只能服务一个Accept（待改进）
- 未经过正式密码学审计（Tamarin/ProVerif）

## 示例

完整可运行的 echo 示例：

```bash
# 终端1：启动服务端
cd examples/echo && go run main.go server

# 终端2：启动客户端
cd examples/echo && go run main.go client
```

## 攻击树

```
攻破 nDTLS 会话
├── 1. MITM          → ✅ 已关闭 (PSK+HMAC 双向认证)
├── 2. 重放          → ✅ 已关闭 (64位 replay bitmap)
├── 3. 弱KDF         → ✅ 已关闭 (HKDF RFC 5869)
├── 4. DoS 洪泛      → ✅ 已关闭 (HelloVerifyRequest Cookie)
└── 5. 流量识别      → ✅ 极低风险 (AnyConnect 指纹)
```

