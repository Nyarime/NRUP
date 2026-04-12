# NRUP

[![CI](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml/badge.svg)](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nrup.svg)](https://pkg.go.dev/github.com/nyarime/nrup)

基于 nDTLS 的可靠加密 UDP 传输协议。通过 FEC 前向纠错与 ARQ 选择性重传的双重机制，在丢包时实现零延迟恢复，极端情况下通过重传保证可靠交付。为高丢包、高延迟的跨国链路和受限网络环境设计。

[English](README_EN.md)

## 安装

```bash
go get github.com/nyarime/nrup@v1.2.0
```

要求 Go 1.22+。

## 架构

```
应用层
  ↓ Write(data)
会话层 (连接管理、迁移、0-RTT恢复)
  ↓
可靠层 ─┬─ FEC (Reed-Solomon, 即时恢复)
        ├─ ARQ (选择性重传, 超时兜底)
        └─ 小包冗余 (<256B 动态2-3份+去重)
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
| 20% 丢包 + 200ms | 90% | ✅ 冗余发送 |
| 30% 丢包 + 200ms | 93% | ✅ 动态冗余 |

### 极端丢包

| 场景 | 握手成功率 | 最佳送达率 |
|------|----------|----------|
| 40% 丢包 + 200ms | 100% | 87% |
| 50% 丢包 + 300ms | 100% | 77% |
| 60% 丢包 + 300ms | 33% | 70% |
| 70% 丢包 + 500ms | 100% | 63% |

测试环境：tc netem 模拟，30 次连接。

## 快速开始

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
```

## 0-RTT 会话恢复

首次握手后缓存 session，后续连接跳过完整握手：

```go
// 首次连接
conn, _ := nrup.Dial(addr, nrup.DefaultConfig())
sessionID := conn.SessionID() // 保存
conn.Close()

// 后续连接（0-RTT）
cfg := nrup.DefaultConfig()
cfg.ResumeID = sessionID
conn, _ = nrup.Dial(addr, cfg) // 跳过完整握手
```

缓存 24 小时有效，HMAC 防重放，过期自动降级到完整握手。

## 配置

```go
cfg := &nrup.Config{
    FECData:              8,                 // 数据分片数
    FECParity:            4,                 // 冗余分片数
    MaxBandwidthMbps:     100,               // BBR 起步参考值
    Cipher:               nrup.CipherAuto,   // 自动选择加密算法
    Disguise:             "anyconnect",      // "anyconnect" / "quic"
    DisguiseSNI:          "example.com",     // QUIC 模式的 SNI
    SmallPacketThreshold: 256,               // 小包冗余阈值
}
```

## 认证模式

```go
// PSK（默认）
cfg := nrup.DefaultConfig()

// Ed25519 公钥签名
cfg := &nrup.Config{
    AuthMode:      "ed25519",
    PrivateKey:    privKey,
    PeerPublicKey: peerPub,
}
```

## 伪装模式

| 模式 | 说明 |
|------|------|
| AnyConnect DTLS（默认） | Cisco AnyConnect cipher suites，可嵌入证书 |
| QUIC | QUIC v1 Initial + Short Header，支持 SNI |

## API

| 方法 | 说明 |
|------|------|
| `nrup.Dial(addr, cfg)` | 连接服务端 |
| `nrup.Listen(addr, cfg)` | 监听端口 |
| `listener.Accept()` | 接受连接 |
| `conn.Read(buf)` | 接收数据 |
| `conn.Write(data)` | 发送数据（小包自动冗余） |
| `conn.GetMetrics()` | 连接指标 |
| `conn.Close()` | 关闭连接 |
| `conn.CloseGraceful()` | 优雅关闭（通知对端） |
| `conn.SessionID()` | 会话标识（用于 0-RTT） |
| `conn.Migrate(addr)` | 连接迁移 |
| `nrup.NewMux(conn)` | 多路复用 |

## 性能

| 指标 | 数值 |
|------|------|
| nDTLS 吞吐 | 108,496 pps |
| 端对端 | 4,089 pps |
| FEC 编码 | 187 MB/s |
| AES-256-GCM | 330 MB/s |
| ChaCha20 | 379 MB/s |
| BBR | 60ns/op, 零内存分配 |

## 安全模型

| 威胁 | 防护 |
|------|------|
| MITM | PSK + HMAC / Ed25519 双向认证 |
| 重放 | 64 位滑动窗口 + 0-RTT HMAC 防重放 |
| 密钥泄露 | X25519 前向保密 |
| 流量识别 | AnyConnect / QUIC 伪装 |
| 密钥派生 | HKDF (RFC 5869) |
| DoS | HelloVerifyRequest Cookie |

## 与 TCP / KCP / QUIC 的区别

|          | TCP    | KCP     | QUIC    | NRUP    |
|----------|--------|---------|---------|---------|
| 传输层    | TCP    | UDP     | UDP     | UDP     |
| 加密      | TLS    | 无      | TLS 1.3 | nDTLS   |
| 丢包恢复  | 重传    | 重传    | 重传     | FEC+ARQ |
| 拥塞控制  | CUBIC  | 自定义  | BBR     | BBR     |
| 队头阻塞  | 有     | 无      | 部分    | 无      |
| 连接迁移  | 无     | 无      | 有      | 有      |
| 0-RTT    | 无     | 无      | 有      | 有      |
| 流量伪装  | 无     | 无      | 无      | AnyConnect/QUIC |

## 许可证

Apache License 2.0
