# NRUP

Reliable UDP transport protocol for Go.

## Features

- **nDTLS** — AES-256-GCM encrypted transport
- **FEC** — Forward error correction with adaptive redundancy
- **BBR** — Congestion control (zero-alloc)
- **Ordered delivery** — Sequence tracking and reordering
- **Keepalive** — Connection health monitoring
- **Memory pool** — Zero GC pressure
- **Stats** — Built-in connection metrics

## Performance

| Metric | Value |
|--------|-------|
| Throughput | 54,602 pps |
| FEC Encode | 118 MB/s |
| AES-GCM | 328 MB/s |
| BBR Wait | 58ns/op, 0 allocs |
| Overhead | 41 bytes/packet |

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
```

## Config

```go
cfg := &nrup.Config{
    FECData:      10,       // data shards
    FECParity:    3,        // parity shards
    MaxBandwidth: 100000000, // 100 Mbps
    IdleTimeout:  120 * time.Second,
    StreamMode:   false,    // datagram mode
}
```

## API

| Type | Description |
|------|-------------|
| `Dial(addr, cfg)` | Connect to server |
| `Listen(addr, cfg)` | Start listener |
| `Conn.Read(buf)` | Receive data |
| `Conn.Write(data)` | Send data |
| `Conn.Stats()` | Connection metrics |
| `Conn.Close()` | Close connection |

## License

Private. See LICENSE.
