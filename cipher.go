package nrup

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherType 加密算法
type CipherType string

const (
	CipherAES256GCM    CipherType = "aes-256-gcm"
	CipherChaCha20     CipherType = "chacha20-poly1305"
	CipherXChaCha20    CipherType = "xchacha20-poly1305"
	CipherAuto         CipherType = "auto" // 根据平台自动选择
)

// newAEAD 创建AEAD加密器
func newAEAD(key []byte, cipherType CipherType) (cipher.AEAD, error) {
	if cipherType == "" || cipherType == CipherAuto {
		cipherType = detectBestCipher()
	}

	switch cipherType {
	case CipherAES256GCM:
		if len(key) < 32 {
			return nil, fmt.Errorf("AES-256-GCM requires 32-byte key, got %d", len(key))
		}
		block, err := aes.NewCipher(key[:32])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)

	case CipherChaCha20:
		if len(key) < 32 {
			return nil, fmt.Errorf("ChaCha20-Poly1305 requires 32-byte key, got %d", len(key))
		}
		return chacha20poly1305.New(key[:32])

	case CipherXChaCha20:
		if len(key) < 32 {
			return nil, fmt.Errorf("XChaCha20-Poly1305 requires 32-byte key, got %d", len(key))
		}
		return chacha20poly1305.NewX(key[:32])

	default:
		return nil, fmt.Errorf("unknown cipher: %s", cipherType)
	}
}

// detectBestCipher 根据平台选择最优算法
func detectBestCipher() CipherType {
	switch runtime.GOARCH {
	case "amd64":
		// x86有AES-NI硬件加速
		return CipherAES256GCM
	case "arm64":
		// ARMv8有AES指令
		return CipherAES256GCM
	case "arm", "mips", "mipsle", "mips64", "mips64le":
		// 低端ARM/MIPS没有AES硬件 → ChaCha20更快
		return CipherChaCha20
	default:
		return CipherAES256GCM
	}
}
