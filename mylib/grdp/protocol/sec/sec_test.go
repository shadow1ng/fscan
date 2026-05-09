package sec

import (
	"testing"

	"github.com/shadow1ng/fscan/mylib/grdp/glog"
	"github.com/shadow1ng/fscan/mylib/grdp/protocol/t125/gcc"
)

func TestGenerateKeysRejectsShortRandoms(t *testing.T) {
	glog.SetLevel(glog.NONE)

	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	if _, _, _, err := generateKeys(clientRandom, nil, gcc.ENCRYPTION_FLAG_128BIT); err == nil {
		t.Fatal("expected error for empty server random")
	}

	if _, _, _, err := generateKeys(nil, serverRandom, gcc.ENCRYPTION_FLAG_128BIT); err == nil {
		t.Fatal("expected error for empty client random")
	}
}

func TestGenerateKeysAcceptsValidRandoms(t *testing.T) {
	glog.SetLevel(glog.NONE)

	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	macKey, decryptKey, encryptKey, err := generateKeys(clientRandom, serverRandom, gcc.ENCRYPTION_FLAG_128BIT)
	if err != nil {
		t.Fatalf("generateKeys returned error for valid randoms: %v", err)
	}
	if len(macKey) != 16 || len(decryptKey) != 16 || len(encryptKey) != 16 {
		t.Fatalf("unexpected key lengths: mac=%d decrypt=%d encrypt=%d", len(macKey), len(decryptKey), len(encryptKey))
	}
}
