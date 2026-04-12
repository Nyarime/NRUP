# Changelog

## v1.0.0 (2026-04-12)

### Features
- nDTLS encrypted transport (AES-256-GCM / ChaCha20-Poly1305 / XChaCha20)
- X25519 ECDHE key exchange
- AnyConnect-compatible DTLS fingerprint
- Reed-Solomon FEC with RTT-aware adaptive redundancy
- ARQ selective retransmission fallback
- BBR congestion control (4-state machine)
- Ordered delivery with timeout-based skip
- Adaptive keepalive (RTT-based interval)
- Session ID for connection migration
- Multi-cipher auto-detection by CPU architecture
- MTU discovery
- Connection statistics

### Security
- HKDF key derivation (RFC 5869)
- 64-bit replay window bitmap
- PSK + HMAC peer authentication
- X25519 forward secrecy

### Performance
- nDTLS: 108K pps
- FEC Encode: 187 MB/s
- AES-256-GCM: 330 MB/s
- ChaCha20-Poly1305: 379 MB/s
- BBR: 60ns/op, 0 allocs
