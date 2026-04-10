# NRUP

Go 语言可靠 UDP 传输协议。

[English](README_EN.md)

## 特性

- **nDTLS** — AES-256-GCM 加密传输
- **FEC** — 前向纠错，自适应冗余
- **BBR** — 拥塞控制（零内存分配）
- **有序交付** — 序列号追踪与重排序
- **心跳保活** — 连接健康监控
- **内存池** — 零 GC 压力
- **连接统计** — 内置指标采集

## 性能

| 指标 | 数值 |
|------|------|
| 吞吐量 | 54,602 pps |
| FEC 编码 | 118 MB/s |
| AES-GCM | 328 MB/s |
| BBR 等待 | 58ns/op, 0 分配 |
| 每包开销 | 41 字节 |

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
```

## 配置

```go
cfg := &nrup.Config{
    FECData:      10,        // 数据分片数
    FECParity:    3,         // 冗余分片数
    MaxBandwidth: 100000000, // 100 Mbps
    IdleTimeout:  120 * time.Second,
    StreamMode:   false,     // 数据报模式
}
```

## API

| 类型 | 说明 |
|------|------|
| `Dial(addr, cfg)` | 连接服务端 |
| `Listen(addr, cfg)` | 启动监听 |
| `Conn.Read(buf)` | 接收数据 |
| `Conn.Write(data)` | 发送数据 |
| `Conn.Stats()` | 连接统计 |
| `Conn.Close()` | 关闭连接 |

## 许可证

私有协议，详见 LICENSE。
