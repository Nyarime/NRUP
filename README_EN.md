# NRUP

[![CI](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml/badge.svg)](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nrup.svg)](https://pkg.go.dev/github.com/nyarime/nrup)

Reliable encrypted UDP transport protocol based on nDTLS. Achieves zero-latency recovery through FEC forward error correction, with ARQ selective retransmission as fallback. Designed for high-loss, high-latency cross-border links.

[中文](README.md)

## Installation

```bash
go get github.com/nyarime/nrup@v1.2.0
```

Requires Go 1.22+.

## Architecture

```
Application
  ↓ Write(data)
Session (connection management, migration, 0-RTT resume)
  ↓
Reliability ─┬─ FEC (Reed-Solomon, instant recovery)
             ├─ ARQ (selective retransmit, timeout fallback)
             └─ Small packet redundancy (<256B, dynamic 2-3x)
  ↓
Congestion (BBR: Pacing + CWND + ProbeRTT)
  ↓
Encryption (nDTLS: AES-GCM / ChaCha20, X25519 handshake)
  ↓
Disguise ─┬─ AnyConnect DTLS (default)
          └─ QUIC v1 (Config.Disguise="quic")
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
| 60% loss + 300ms | 33% | 70% |
| 70% loss + 500ms | 100% | 63% |

Tested with tc netem, 30 connections per scenario.

## Quick Start

```go
import "github.com/nyarime/nrup"

// Server
listener, _ := nrup.Listen(":4000", nrup.DefaultConfig())
conn, _ := listener.Accept()
defer conn.Close()

buf := make([]byte, 4096)
n, _ := conn.Read(buf)
conn.Write(buf[:n])

// Client
conn, _ := nrup.Dial("server:4000", nrup.DefaultConfig())
defer conn.Close()

conn.Write([]byte("hello"))
n, _ := conn.Read(buf)
```

## 0-RTT Session Resumption

Cache session after first handshake, skip full handshake on reconnect:

```go
// First connection
conn, _ := nrup.Dial(addr, nrup.DefaultConfig())
sessionID := conn.SessionID() // save this
conn.Close()

// Subsequent connection (0-RTT)
cfg := nrup.DefaultConfig()
cfg.ResumeID = sessionID
conn, _ = nrup.Dial(addr, cfg) // skips full handshake
```

Cache valid for 24 hours. HMAC anti-replay. Auto-fallback to full handshake on expiry.

## Configuration

```go
cfg := &nrup.Config{
    FECData:              8,                 // Data shards
    FECParity:            4,                 // Parity shards
    MaxBandwidthMbps:     100,               // BBR initial reference
    Cipher:               nrup.CipherAuto,   // Auto-detect
    Disguise:             "anyconnect",      // "anyconnect" / "quic"
    DisguiseSNI:          "example.com",     // SNI for QUIC mode
    SmallPacketThreshold: 256,               // Small packet redundancy threshold
}
```

## Authentication

```go
// PSK (default)
cfg := nrup.DefaultConfig()

// Ed25519 public key
cfg := &nrup.Config{
    AuthMode:      "ed25519",
    PrivateKey:    privKey,
    PeerPublicKey: peerPub,
}
```

## Disguise Modes

| Mode | Description |
|------|-------------|
| AnyConnect DTLS (default) | Cisco AnyConnect cipher suites, optional cert embedding |
| QUIC | QUIC v1 Initial + Short Header with SNI |

## API

| Method | Description |
|--------|-------------|
| `nrup.Dial(addr, cfg)` | Connect to server |
| `nrup.Listen(addr, cfg)` | Listen on address |
| `listener.Accept()` | Accept connection |
| `conn.Read(buf)` | Receive data |
| `conn.Write(data)` | Send data (auto small-packet redundancy) |
| `conn.GetMetrics()` | Connection metrics |
| `conn.Close()` | Close connection |
| `conn.CloseGraceful()` | Graceful close (notify peer) |
| `conn.SessionID()` | Session ID (for 0-RTT) |
| `conn.Migrate(addr)` | Connection migration |
| `nrup.NewMux(conn)` | Stream multiplexer |

## Performance

| Metric | Value |
|--------|-------|
| nDTLS throughput | 108,496 pps |
| End-to-end | 4,089 pps |
| FEC encode | 187 MB/s |
| AES-256-GCM | 330 MB/s |
| ChaCha20 | 379 MB/s |
| BBR | 60ns/op, 0 allocs |

## Security

| Threat | Mitigation |
|--------|-----------|
| MITM | PSK + HMAC / Ed25519 mutual auth |
| Replay | 64-bit sliding window + 0-RTT HMAC |
| Key compromise | X25519 forward secrecy |
| Traffic analysis | AnyConnect / QUIC disguise |
| Key derivation | HKDF (RFC 5869) |
| DoS | HelloVerifyRequest Cookie |

## vs TCP / KCP / QUIC

|          | TCP    | KCP     | QUIC    | NRUP    |
|----------|--------|---------|---------|---------|
| Transport | TCP   | UDP     | UDP     | UDP     |
| Encryption | TLS  | None    | TLS 1.3 | nDTLS  |
| Loss Recovery | Retransmit | Retransmit | Retransmit | FEC+ARQ |
| Congestion | CUBIC | Custom  | BBR     | BBR     |
| HOL Blocking | Yes | No     | Partial | No      |
| Migration | No    | No      | Yes     | Yes     |
| 0-RTT | No     | No      | Yes     | Yes     |
| Disguise | None   | None    | None    | AnyConnect/QUIC |

## License

Apache License 2.0
