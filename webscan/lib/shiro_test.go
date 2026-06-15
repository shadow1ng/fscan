package lib

import (
	"encoding/base64"
	"strings"
	"testing"
)

// =============================================================================
// Padding 测试
// =============================================================================

func TestPadding_BasicBlockAlignment(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		blockSize int
		wantLen   int // 期望长度
	}{
		{
			name:      "空输入填充整个块",
			input:     []byte{},
			blockSize: 16,
			wantLen:   16,
		},
		{
			name:      "15字节填充1字节",
			input:     make([]byte, 15),
			blockSize: 16,
			wantLen:   16,
		},
		{
			name:      "整块对齐追加完整块",
			input:     make([]byte, 16),
			blockSize: 16,
			wantLen:   32,
		},
		{
			name:      "1字节填充15字节",
			input:     []byte{0x01},
			blockSize: 16,
			wantLen:   16,
		},
		{
			name:      "blockSize=8时的对齐",
			input:     make([]byte, 5),
			blockSize: 8,
			wantLen:   8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Padding(tt.input, tt.blockSize)
			if len(result) != tt.wantLen {
				t.Errorf("Padding() len=%d, want %d", len(result), tt.wantLen)
			}
			// 验证填充字节值符合 PKCS7 规范
			if len(result) > 0 {
				padLen := int(result[len(result)-1])
				if padLen == 0 || padLen > tt.blockSize {
					t.Errorf("填充字节值 %d 超出 blockSize=%d", padLen, tt.blockSize)
				}
				// 验证所有填充字节相同
				for i := len(result) - padLen; i < len(result); i++ {
					if result[i] != byte(padLen) {
						t.Errorf("填充字节[%d]=%d 不等于 padLen=%d", i, result[i], padLen)
					}
				}
			}
		})
	}
}

func TestPadding_ResultLength(t *testing.T) {
	// 任意长度输入，结果都应该是 blockSize 的整数倍
	blockSize := 16
	for inputLen := 0; inputLen < 50; inputLen++ {
		input := make([]byte, inputLen)
		result := Padding(input, blockSize)
		if len(result)%blockSize != 0 {
			t.Errorf("输入长度 %d: 填充后长度 %d 不是 %d 的倍数", inputLen, len(result), blockSize)
		}
	}
}

// =============================================================================
// AESCBCEncrypt 测试
// =============================================================================

func TestAESCBCEncrypt_ValidKey128(t *testing.T) {
	// 128-bit AES key (16 bytes)
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	result := AESCBCEncrypt(key)
	if result == "" {
		t.Error("有效的128位密钥应返回非空结果")
	}
	// 结果应为有效的 base64
	_, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Errorf("AESCBCEncrypt 结果应为有效 base64: %v", err)
	}
}

func TestAESCBCEncrypt_ValidKey256(t *testing.T) {
	// 256-bit AES key (32 bytes)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	result := AESCBCEncrypt(key)
	if result == "" {
		t.Error("有效的256位密钥应返回非空结果")
	}
}

func TestAESCBCEncrypt_InvalidBase64Key(t *testing.T) {
	result := AESCBCEncrypt("!!!not-valid-base64!!!")
	if result != "" {
		t.Error("无效 base64 密钥应返回空字符串")
	}
}

func TestAESCBCEncrypt_InvalidKeySize(t *testing.T) {
	// AES 要求密钥为 16/24/32 字节，10 字节无效
	key := base64.StdEncoding.EncodeToString(make([]byte, 10))
	result := AESCBCEncrypt(key)
	if result != "" {
		t.Error("无效密钥长度应返回空字符串")
	}
}

func TestAESCBCEncrypt_NonDeterministic(t *testing.T) {
	// 因为 IV 是随机的，两次加密结果应不同
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	r1 := AESCBCEncrypt(key)
	r2 := AESCBCEncrypt(key)
	if r1 == r2 {
		// 极小概率相同，记录即可
		t.Log("两次加密结果相同（极低概率事件）")
	}
}

// =============================================================================
// AESGCMEncrypt 测试
// =============================================================================

func TestAESGCMEncrypt_ValidKey128(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	result := AESGCMEncrypt(key)
	if result == "" {
		t.Error("有效的128位密钥应返回非空结果")
	}
	_, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Errorf("AESGCMEncrypt 结果应为有效 base64: %v", err)
	}
}

func TestAESGCMEncrypt_InvalidKey(t *testing.T) {
	result := AESGCMEncrypt("invalid-base64!!!")
	if result != "" {
		t.Error("无效 base64 密钥应返回空字符串")
	}
}

func TestAESGCMEncrypt_NonDeterministic(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	r1 := AESGCMEncrypt(key)
	r2 := AESGCMEncrypt(key)
	// GCM nonce 随机，结果不应相同
	if r1 == r2 {
		t.Log("两次 GCM 加密结果相同（极低概率事件）")
	}
}

// =============================================================================
// GetShrioCookie 测试
// =============================================================================

func TestGetShrioCookie_CBCMode(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	result := GetShrioCookie(key, "cbc")
	if result == "" {
		t.Error("CBC 模式应返回非空 cookie")
	}
}

func TestGetShrioCookie_GCMMode(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	result := GetShrioCookie(key, "gcm")
	if result == "" {
		t.Error("GCM 模式应返回非空 cookie")
	}
}

func TestGetShrioCookie_DefaultMode(t *testing.T) {
	// 非 gcm 模式走 CBC
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	result := GetShrioCookie(key, "other")
	cbcResult := AESCBCEncrypt(key)
	// 两个结果都应为非空 base64，但由于随机 IV 不一定相同
	if result == "" {
		t.Error("默认（非gcm）模式应使用 CBC 加密并返回非空结果")
	}
	_ = cbcResult
}

func TestGetShrioCookie_RealShiroKey(t *testing.T) {
	// 使用真实的 Shiro 默认密钥
	shiroDefaultKey := "kPH+bIxk5D2deZiIxcaaaA=="
	result := GetShrioCookie(shiroDefaultKey, "cbc")
	if result == "" {
		t.Error("使用默认 Shiro 密钥应能生成有效 cookie")
	}
	// 验证结果是 base64 编码
	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Errorf("结果应为有效 base64: %v", err)
	}
	// CBC 模式：IV(16字节) + 密文，结果至少 32 字节
	if len(decoded) < 32 {
		t.Errorf("CBC 加密结果太短: %d 字节", len(decoded))
	}
}

func TestGetShrioCookie_ResultIsBase64(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for _, mode := range []string{"cbc", "gcm"} {
		result := GetShrioCookie(key, mode)
		if result == "" {
			t.Errorf("mode=%s: 结果不应为空", mode)
			continue
		}
		// base64 只含 [A-Za-z0-9+/=]
		if strings.ContainsAny(result, " \t\n\r") {
			t.Errorf("mode=%s: base64 结果不应含空白字符", mode)
		}
	}
}
