// Package nrup implements a reliable encrypted UDP transport protocol
// with FEC forward error correction and ARQ selective retransmission.
//
// NRUP achieves zero-latency packet loss recovery in most scenarios
// and falls back to retransmission for extreme cases. It is designed
// for high-loss, high-latency cross-border links and censored networks.
//
// # Quick Start
//
//	// Server
//	listener, _ := nrup.Listen(":4000", nrup.DefaultConfig())
//	conn, _ := listener.Accept()
//	buf := make([]byte, 4096)
//	n, _ := conn.Read(buf)
//	conn.Write(buf[:n])
//
//	// Client
//	conn, _ := nrup.Dial("server:4000", nrup.DefaultConfig())
//	conn.Write([]byte("hello"))
//	n, _ := conn.Read(buf)
//
// # Features
//
//   - FEC + ARQ dual recovery: zero-latency for normal loss, retransmit for extreme
//   - Small packet redundancy: packets <256B sent twice with dedup
//   - Traffic disguise: AnyConnect DTLS / QUIC wire format
//   - BBR congestion control with zero-alloc pacing
//   - Ed25519 + PSK dual authentication modes
//   - Connection migration and session resumption
//   - Stream multiplexing via [NewMux]
//
// # Architecture
//
//	Core:
//	  nrup.go          - Conn, Config, Read/Write
//	  dial.go          - Dial, Listen, Accept
//
//	Encryption:
//	  ndtls.go         - nDTLS record layer (AES-GCM / ChaCha20)
//	  handshake.go     - X25519 key exchange, AnyConnect fingerprint
//	  cipher.go        - Multi-cipher auto-detection
//
//	Reliability:
//	  fec.go           - Reed-Solomon FEC encoding/decoding
//	  fec_adaptive.go  - RTT-aware adaptive redundancy
//	  retransmit.go    - ARQ selective retransmission
//	  ordered.go       - Ordered delivery with timeout skip
//	  seq.go           - Sequence tracking and RTT measurement
//	  frame.go         - Wire frame encoding/decoding
//
//	Control:
//	  congestion.go    - BBR congestion control (4-state machine)
//	  congestion_flow.go - Flow control (sync.Cond based)
//	  keepalive.go     - Adaptive keepalive
//
//	Multiplexing:
//	  mux.go           - Stream multiplexer
//	  demux.go         - UDP packet demultiplexer
//
//	Utility:
//	  session.go       - Session management and migration
//	  resume.go        - 0-RTT session resumption
//	  pool.go          - Buffer pool (zero GC pressure)
//	  dual.go          - TCP+UDP dual channel
//	  fast.go          - FastConn (raw UDP + AES-GCM)
//	  quic_disguise.go - QUIC wire format disguise
package nrup
