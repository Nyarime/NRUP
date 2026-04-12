# NRUP

基于 nDTLS 的可靠加密 UDP 传输协议。通过 FEC 前向纠错与 ARQ 选择性重传的双重机制，在丢包时实现零延迟恢复，极端情况下通过重传保证可靠交付。为高丢包、高延迟的跨国链路和受限网络环境设计。

[English](README_EN.md)

## 概述

NRUP 在 UDP 之上构建了一套完整的可靠传输机制，同时保持 UDP 的低延迟特性。协议支持 AnyConnect 兼容 DTLS 和 QUIC 两种线上格式，与标准协议流量不可区分。

核心设计目标：
- **零延迟丢包恢复**：FEC 前向纠错即时恢复，ARQ 重传兜底，避免 TCP 的队头阻塞
- **自适应网络变化**：BBR 拥塞控制 + RTT 感知的 FEC 冗余调整
- **流量伪装**：AnyConnect DTLS / QUIC 双模式，DPI 无法区分
- **跨平台零依赖**：纯 Go 实现，支持 x86 / ARM / MIPS 交叉编译

## 架构

```
应用层
  ↓ Write(data)
会话层 (连接管理、迁移、有序交付)
  ↓
可靠层 ─┬─ FEC (Reed-Solomon, 即时恢复)
        ├─ ARQ (选择性重传, 超时兜底)
        └─ 小包冗余 (<256B 自动双发+去重)
  ↓
拥塞层 (BBR: Pacing + CWND + ProbeRTT)
  ↓
加密层 (nDTLS: AES-GCM / ChaCha20, X25519 握手)
  ↓
伪装层 ─┬─ AnyConnect DTLS (默认)
        └─ QUIC v1 (Config.Disguise="quic")
  ↓
UDP
```

## 弱网实测

| 场景 | 送达率 | 说明 |
|------|--------|------|
| 正常网络 | 100% | ✅ |
| 1% 丢包 + 50ms | 100% | ✅ FEC 全恢复 |
| 5% 丢包 + 100ms | 100% | ✅ FEC 全恢复 |
| 10% 丢包 + 100ms | 100% | ✅ FEC + ARQ |
| 20% 丢包 + 200ms | 63%+ | ⚠️ 可连可传 |
| 30% 丢包 + 200ms | 90% | ✅ 小包冗余 |

测试环境：tc netem 模拟，30 次连接。

## 与 TCP / KCP / QUIC 的区别

|          | TCP    | KCP     | QUIC    | NRUP    |
|----------|--------|---------|---------|---------|
| 传输层    | TCP    | UDP     | UDP     | UDP     |
| 加密      | TLS    | 无      | TLS 1.3 | nDTLS   |
| 丢包恢复  | 重传    | 重传    | 重传     | FEC+ARQ |
| 拥塞控制  | CUBIC  | 自定义  | BBR     | BBR     |
| 队头阻塞  | 有     | 无      | 部分    | 无      |
| 连接迁移  | 无     | 无      | 有      | 有      |
| 流量伪装  | 无     | 无      | 无      | AnyConnect/QUIC |

## 性能

| 指标 | 数值 | 说明 |
|------|------|------|
| nDTLS 吞吐 | 108,496 pps | 纯加密收发 |
| 端对端 | 4,089 pps | 含 FEC + BBR |
| FEC 编码 | 187 MB/s | Reed-Solomon SIMD |
| AES-256-GCM | 330 MB/s | x86 AES-NI |
| ChaCha20 | 379 MB/s | ARM 友好 |
| BBR | 60ns/op | 零内存分配 |

## 使用

```go
import "github.com/nyarime/nrup"

// 服务端
listener, _ := nrup.Listen(":4000", nrup.DefaultConfig())
conn, _ := listener.Accept()
defer conn.Close()

buf := make([]byte, 4096)
n, _ := conn.Read(buf)
conn.Write(buf[:n])

// 客户端
conn, _ := nrup.Dial("server:4000", nrup.DefaultConfig())
defer conn.Close()

conn.Write([]byte("hello"))
n, _ := conn.Read(buf)

// 指标
metrics := conn.GetMetrics()
```

## 配置

```go
cfg := &nrup.Config{
    FECData:          8,                     // 数据分片数
    FECParity:        4,                     // 冗余分片数
    MaxBandwidthMbps: 100,                   // BBR 起步参考值
    Cipher:           nrup.CipherAuto,       // 自动选择加密算法
    Disguise:         "anyconnect",          // "anyconnect" / "quic"
    DisguiseSNI:      "example.com",         // QUIC 模式的 SNI
}
```

## 伪装模式

### AnyConnect DTLS（默认）

```
ClientHello/ServerHello: Cisco AnyConnect cipher suites
Certificate: 可嵌入 TLS 证书 (Config.CertDER)
数据帧: DTLS 1.2 记录层格式
```

### QUIC

```
握手: QUIC v1 Initial 包格式 (含 SNI)
数据帧: QUIC Short Header
```

## API

| 方法 | 说明 |
|------|------|
| `nrup.Dial(addr, cfg)` | 连接服务端 |
| `nrup.Listen(addr, cfg)` | 监听端口 |
| `listener.Accept()` | 接受连接 |
| `conn.Read(buf)` | 接收数据 |
| `conn.Write(data)` | 发送数据 |
| `conn.GetMetrics()` | 连接指标 |
| `conn.Migrate(addr)` | 连接迁移 |
| `conn.SessionID()` | 会话标识 |
| `conn.Close()` | 关闭连接 |
| `nrup.NewMux(conn)` | 多路复用 |

## 安全模型

| 威胁 | 防护 |
|------|------|
| MITM | PSK + HMAC 双向认证 |
| 重放 | 64 位滑动窗口 |
| 密钥泄露 | X25519 前向保密 |
| 流量识别 | AnyConnect / QUIC 伪装 |
| 密钥派生 | HKDF (RFC 5869) |
| DoS | HelloVerifyRequest Cookie |

### 已知限制

- Ed25519 认证待集成
- 20%+ 丢包场景握手可靠性仍有提升空间

## 许可证

Apache License 2.0
