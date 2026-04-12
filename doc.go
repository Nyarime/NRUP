// Package nrup implements a reliable encrypted UDP transport protocol.
//
// Architecture (file organization):
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
//	Utility:
//	  session.go       - Session management and migration
//	  pool.go          - Buffer pool (zero GC pressure)
//	  dual.go          - TCP+UDP dual channel
//	  fast.go          - FastConn (raw UDP + AES-GCM)
package nrup
