package nrup

import (
	"testing"
)

func TestLTCodecCreate(t *testing.T) {
	lt := NewLTCodec(10)
	if lt == nil {
		t.Fatal("❌ LT codec创建失败")
	}
	if lt.Type() != "lt" {
		t.Fatalf("❌ Type=%s, want lt", lt.Type())
	}
	t.Log("✅ LT codec创建成功")
}

func TestLTCodecEncode(t *testing.T) {
	lt := NewLTCodec(8)
	data := []byte("Hello, this is a test message for LT fountain code encoding!")
	
	blocks := lt.EncodeLT(data, 12) // 12个编码块(8source+4repair)
	if len(blocks) != 12 {
		t.Fatalf("❌ blocks=%d, want 12", len(blocks))
	}
	t.Logf("✅ LT编码: %d字节 → %d块", len(data), len(blocks))
}

func TestFECFactory(t *testing.T) {
	// RS默认
	rs := NewFECByType("", 10, 3)
	if rs == nil { t.Fatal("❌ RS创建失败") }
	if rs.useLDPC { t.Fatal("❌ RS不应该useLDPC") }
	t.Log("✅ RS FEC创建")

	// LDPC
	ldpcFEC := NewFECByType(FECTypeLDPC, 10, 4)
	if ldpcFEC == nil { t.Fatal("❌ LDPC创建失败") }
	if !ldpcFEC.useLDPC { t.Fatal("❌ LDPC应该useLDPC=true") }
	t.Log("✅ LDPC FEC创建(GoFEC PEG)")
}
