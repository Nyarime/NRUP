# NRUP

Reliable encrypted UDP transport protocol built on nDTLS. Uses FEC forward error correction with ARQ retransmission fallback — zero-delay recovery for normal packet loss, guaranteed delivery for extreme loss. Designed for lossy, high-latency cross-border and restricted networks.

[中文](README.md)

## Overview

NRUP builds a complete reliable transport layer on top of UDP while preserving its low-latency characteristics. The protocol uses an nDTLS encryption layer, making traffic indistinguishable from standard DTLS 1.2.

Design goals:
- **Zero-delay loss recovery**: FEC instant recovery + ARQ retransmission fallback, no head-of-line blocking
- **Adaptive to network conditions**: BBR congestion control + RTT-aware FEC redundancy
- **Encrypted and unidentifiable**: AES-256-GCM / ChaCha20-Poly1305, DTLS 1.2 wire format
- **Cross-platform**: Pure Go, supports x86 / ARM / MIPS cross-compilation

## Performance

| Metric | Value |
|--------|-------|
| nDTLS throughput | 108,496 pps |
| End-to-end | 4,089 pps |
| FEC Encode | 187 MB/s (SIMD) |
| AES-256-GCM | 330 MB/s (AES-NI) |
| ChaCha20 | 379 MB/s |
| BBR Wait | 60ns/op, 0 allocs |
| Per-packet overhead | 41 bytes |

## Usage

```go
import "github.com/nyarime/nrup"

// Server
listener, _ := nrup.Listen(":4000", nrup.DefaultConfig())
nrup, _ := listener.Accept()
conn.Write(data)

// Client
conn, _ := nrup.Dial("server:4000", nrup.DefaultConfig())
conn.Write([]byte("hello"))
conn.Read(buf)

// Stats
stats := conn.Stats()
fmt.Printf("RTT: %v, Loss: %.1f%%\n", stats.RTT, stats.LossRate*100)
```

## Config

```go
cfg := &nrup.Config{
    FECData:      10,
    FECParity:    3,
    MaxBandwidthMbps: 100,                   // BBR initial estimate, not hard cap
    Cipher:       nrup.CipherAuto,       // auto-detect
    IdleTimeout:  120 * time.Second,
    StreamMode:   false,                 // false=datagram(FEC+BBR) true=stream(passthrough)
}
```

## License

Apache License 2.0

## Attack Tree

```
Break nDTLS Session
├── 1. MITM           → ✅ Closed (PSK+HMAC mutual auth)
├── 2. Replay         → ✅ Closed (64-bit sliding window)
├── 3. Weak KDF       → ✅ Closed (HKDF RFC 5869)
├── 4. DoS Flood      → ✅ Closed (HelloVerifyRequest Cookie)
└── 5. Traffic ID     → ✅ Very Low (AnyConnect fingerprint)
```
