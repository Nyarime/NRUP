package nrup

// FECEncoder FEC编解码接口
// v1.5.0: 支持RS(默认) + RaptorQ + LDPC(v1.5.1)
type FECEncoder interface {
	// Encode 编码数据为多个分片(data+parity)
	Encode(data []byte) [][]byte
	// Decode 从分片恢复数据(容忍丢失)
	Decode(shards [][]byte) ([]byte, error)
	// Type 返回编码类型
	Type() string
}

// FECType FEC编码类型
type FECType string

const (
	FECTypeRS       FECType = "rs"       // Reed-Solomon (默认)
	FECTypeRaptorQ  FECType = "raptorq"  // RaptorQ (v1.5.0)
	FECTypeLDPC     FECType = "ldpc"     // LDPC (v1.5.1辅助)
)
