package nrup

import (
	"sync"
)

// Buffer pools 减少内存分配和GC压力
var (
	// 小帧池（FEC帧，通常<200字节）
	smallBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 256)
			return &buf
		},
	}

	// 中帧池（数据包，通常<1500字节）
	mediumBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 1500)
			return &buf
		},
	}

	// 大帧池（读缓冲，最大64KB）
	largeBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 65536)
			return &buf
		},
	}

	// FEC分片池
	shardPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 256)
			return &buf
		},
	}
)

// GetSmallBuf 获取小缓冲
func GetSmallBuf() *[]byte  { return smallBufPool.Get().(*[]byte) }
// PutSmallBuf 归还小缓冲
func PutSmallBuf(b *[]byte) { smallBufPool.Put(b) }

// GetLargeBuf 获取大缓冲
func GetLargeBuf() *[]byte  { return largeBufPool.Get().(*[]byte) }
// PutLargeBuf 归还大缓冲
func PutLargeBuf(b *[]byte) { largeBufPool.Put(b) }
