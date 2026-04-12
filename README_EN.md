# NRUP

[![CI](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml/badge.svg)](https://github.com/Nyarime/NRUP/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nrup.svg)](https://pkg.go.dev/github.com/nyarime/nrup)

Reliable encrypted UDP transport protocol based on nDTLS. Achieves zero-latency recovery through FEC forward error correction, with ARQ selective retransmission as fallback. Designed for high-loss, high-latency cross-border links.

[中文](README.md)

## Installation

```bash
go get github.com/nyarime/nrup@v1.1.0
```

Requires Go 1.22+.

## Overview

NRUP builds a complete reliable transport mechanism on top of UDP while preserving UDP's low-latency characteristics. Supports AnyConnect-compatible DTLS and QUIC wire formats, indistinguishable from standard protocol traffic.

- **Zero-latency loss recovery**: FEC instant recovery + ARQ retransmission fallback
- **Adaptive**: BBR congestion control + RTT-aware FEC redundancy
- **Traffic disguise**: AnyConnect DTLS / QUIC dual mode
- **Cross-platform**: Pure Go, supports x86 / ARM / MIPS

## Weak Network Performance

| Scenario | Delivery Rate | Status |
|----------|--------------|--------|
| Normal | 100% | ✅ |
| 1% loss + 50ms | 100% | ✅ FEC recovery |
| 5% loss + 100ms | 100% | ✅ FEC recovery |
| 10% loss + 100ms | 100% | ✅ FEC + ARQ |
| 20% loss + 200ms | 90% | ✅ Redundant send |
| 30% loss + 200ms | 93% | ✅ Small packet redundancy |

Tested with tc netem, 30 connections per scenario.

### Extreme Packet Loss

| Scenario | Handshake | Best Delivery |
|----------|-----------|---------------|
| 40% loss + 200ms | 67% | 93% |
| 50% loss + 300ms | 67% | 73% |
| 60% loss + 300ms | 33% | 67% |
| 70% loss + 500ms | 33% | 50% |

## vs TCP / KCP / QUIC

|          | TCP    | KCP     | QUIC    | NRUP    |
|----------|--------|---------|---------|---------|
| Transport | TCP   | UDP     | UDP     | UDP     |
| Encryption | TLS  | None    | TLS 1.3 | nDTLS  |
| Loss Recovery | Retransmit | Retransmit | Retransmit | FEC+ARQ |
| Congestion | CUBIC | Custom  | BBR     | BBR     |
| HOL Blocking | Yes | No     | Partial | No      |
| Migration | No    | No      | Yes     | Yes     |
| Disguise | None   | None    | None    | AnyConnect/QUIC |

## Performance

| Metric | Value |
|--------|-------|
| nDTLS throughput | 108,496 pps |
| End-to-end | 4,089 pps |
| FEC encode | 187 MB/s |
| AES-256-GCM | 330 MB/s |
| ChaCha20 | 379 MB/s |
| BBR | 60ns/op, 0 allocs |

## Usage

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

// Metrics
metrics := conn.GetMetrics()
```

## Configuration

```go
cfg := &nrup.Config{
    FECData:          8,                  // Data shards
    FECParity:        4,                  // Parity shards
    MaxBandwidthMbps: 100,                // BBR initial reference
    Cipher:           nrup.CipherAuto,    // Auto-detect
    Disguise:         "anyconnect",       // "anyconnect" / "quic"
    DisguiseSNI:      "example.com",      // SNI for QUIC mode
}
```

## Disguise Modes

### AnyConnect DTLS (default)

Handshake mimics Cisco AnyConnect VPN. Optional certificate embedding via `Config.CertDER`.

### QUIC

QUIC v1 Initial packet format with SNI. Short Header for data frames.

## API

| Method | Description |
|--------|-------------|
| `nrup.Dial(addr, cfg)` | Connect to server |
| `nrup.Listen(addr, cfg)` | Listen on address |
| `listener.Accept()` | Accept connection |
| `conn.Read(buf)` | Receive data |
| `conn.Write(data)` | Send data |
| `conn.GetMetrics()` | Connection metrics |
| `conn.Migrate(addr)` | Connection migration |
| `conn.SessionID()` | Session identifier |
| `nrup.NewMux(conn)` | Stream multiplexer |

## Security

| Threat | Mitigation |
|--------|-----------|
| MITM | PSK + HMAC mutual auth |
| Replay | 64-bit sliding window |
| Key compromise | X25519 forward secrecy |
| Traffic analysis | AnyConnect / QUIC disguise |
| Key derivation | HKDF (RFC 5869) |
| DoS | HelloVerifyRequest Cookie |

### Known Limitations

- Ed25519 auth pending integration
- Handshake reliability in 20%+ loss still improving

## License

Apache License 2.0
