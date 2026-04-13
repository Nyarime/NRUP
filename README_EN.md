# NRUP

[![CI](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml/badge.svg)](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nrup.svg)](https://pkg.go.dev/github.com/nyarime/nrup)

Reliable encrypted UDP transport protocol based on nDTLS. FEC forward error correction for zero-latency recovery, ARQ selective retransmission as fallback. Designed for high-loss, high-latency cross-border links.

[中文](README.md)

## Installation

```bash
go get github.com/nyarime/nrup@v1.2.1
```

Requires Go 1.22+.

## Three-Tier Mode

| Mode | Disguise | Cipher | Overhead | Use Case |
|------|----------|--------|----------|----------|
| Public | `anyconnect` | `auto` | 41B/pkt | Cross-border, censored networks (default) |
| Dedicated | `none` | `auto` | 28B/pkt | Encrypted, no DPI evasion needed |
| Internal | `none` | `none` | 0B/pkt | Pure reliable UDP (LAN/gaming) |

FEC + ARQ + BBR retained in all three modes.

## Architecture

```
Application
  ↓ Write(data)
Session (management, migration, 0-RTT resume)
  ↓
Reliability ─┬─ FEC (Reed-Solomon, instant recovery)
             ├─ ARQ (selective retransmit, timeout fallback)
             └─ Small packet redundancy (<256B, dynamic 2-3x)
  ↓
Congestion (BBR: Pacing + CWND + ProbeRTT)
  ↓
Encryption (nDTLS: AES-GCM / ChaCha20 / None)
  ↓
Disguise ─┬─ AnyConnect DTLS (default)
          ├─ QUIC v1
          └─ None (raw UDP)
  ↓
UDP
```

## Weak Network Performance

| Scenario | Delivery Rate | Status |
|----------|--------------|--------|
| Normal | 100% | ✅ |
| 1% loss + 50ms | 100% | ✅ FEC recovery |
| 5% loss + 100ms | 100% | ✅ FEC recovery |
| 10% loss + 100ms | 100% | ✅ FEC + ARQ |
| 20% loss + 200ms | 90% | ✅ Redundant send |
| 30% loss + 200ms | 93% | ✅ Dynamic redundancy |

### Extreme Packet Loss

| Scenario | Handshake | Best Delivery |
|----------|-----------|---------------|
| 40% loss + 200ms | 100% | 87% |
| 50% loss + 300ms | 100% | 77% |
| 70% loss + 500ms | 100% | 63% |

## Quick Start

```go
import "github.com/nyarime/nrup"

// Server
listener, _ := nrup.Listen(":4000", nrup.DefaultConfig())
conn, _ := listener.Accept()
buf := make([]byte, 4096)
n, _ := conn.Read(buf)
conn.Write(buf[:n])

// Client
conn, _ := nrup.Dial("server:4000", nrup.DefaultConfig())
conn.Write([]byte("hello"))
n, _ := conn.Read(buf)
```

## Configuration

```go
// Public (default)
cfg := nrup.DefaultConfig()

// Dedicated line (encrypted, no disguise)
cfg := &nrup.Config{Disguise: "none", Cipher: nrup.CipherAuto}

// Internal (pure reliable UDP)
cfg := &nrup.Config{Disguise: "none", Cipher: nrup.CipherNone}
```

## 0-RTT Session Resumption

```go
conn, _ := nrup.Dial(addr, nrup.DefaultConfig())
sessionID := conn.SessionID()
conn.Close()

cfg := nrup.DefaultConfig()
cfg.ResumeID = sessionID
conn, _ = nrup.Dial(addr, cfg) // skips full handshake
```

## vs TCP / KCP / QUIC

|          | TCP    | KCP     | QUIC    | NRUP    |
|----------|--------|---------|---------|---------|
| Transport | TCP   | UDP     | UDP     | UDP     |
| Encryption | TLS  | None    | TLS 1.3 | nDTLS/None |
| Loss Recovery | Retransmit | Retransmit | Retransmit | FEC+ARQ |
| Congestion | CUBIC | Custom  | BBR     | BBR     |
| HOL Blocking | Yes | No     | Partial | No      |
| 0-RTT | No     | No      | Yes     | Yes     |
| Disguise | None   | None    | None    | AnyConnect/QUIC |
| No-encrypt mode | No | Yes  | No      | Yes     |

## License

Apache License 2.0
