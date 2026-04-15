package nrup

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func BenchmarkFECEncodeTypes(b *testing.B) {
	types := []FECType{FECTypeRS, FECTypeLDPC}
	sizes := []int{512, 1024, 4096}

	for _, ft := range types {
		for _, sz := range sizes {
			b.Run(fmt.Sprintf("%s_%dB", ft, sz), func(b *testing.B) {
				fec := NewFECByType(ft, 8, 4)
				data := make([]byte, sz)
				rand.Read(data)
				b.SetBytes(int64(sz))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					fec.Encode(data)
				}
			})
		}
	}
}

func TestFECEndToEnd(t *testing.T) {
	types := []FECType{FECTypeRS, FECTypeLDPC}
	lossRates := []float64{0.0, 0.05, 0.10, 0.20, 0.30}

	for _, ft := range types {
		fec := NewFECByType(ft, 8, 4)

		for _, loss := range lossRates {
			t.Run(fmt.Sprintf("%s_loss%.0f%%", ft, loss*100), func(t *testing.T) {
				recovered := 0
				failed := 0
				total := 50
				rng := rand.New(rand.NewSource(time.Now().UnixNano()))

				for i := 0; i < total; i++ {
					data := make([]byte, 1024)
					rng.Read(data)

					// 编码
					frames := fec.Encode(data)

					// 模拟丢包: 随机丢弃帧
					for _, frame := range frames {
						if rng.Float64() < loss {
							continue // 丢弃
						}
						result := fec.Decode(frame)
						if result != nil {
							recovered++
						}
					}
				}

				_ = failed
				rate := float64(recovered) / float64(total) * 100
				t.Logf("%s @ %.0f%%丢包: 恢复率 %.1f%% (%d/%d)", ft, loss*100, rate, recovered, total)
			})
		}
	}
}
