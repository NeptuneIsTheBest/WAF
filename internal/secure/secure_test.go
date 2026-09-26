package secure

import (
	"bytes"
	"testing"
	"time"
)

func TestPasswordsAndAuthenticatedEncryption(t *testing.T) {
	hash, err := Password("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") || VerifyPassword(hash, "wrong") {
		t.Fatal("password verification")
	}
	key := bytes.Repeat([]byte{1}, 32)
	encrypted, err := Seal(key, "credential:one", []byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Open(key, "credential:one", encrypted)
	if err != nil || string(plain) != "token" {
		t.Fatal(err)
	}
	if _, err = Open(key, "credential:two", encrypted); err == nil {
		t.Fatal("AAD did not bind credential identity")
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, err = Open(key, "credential:one", encrypted); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestTOTPReplayAndRFCVector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // gitleaks:allow RFC 6238 public test vector.
	now := time.Unix(59, 0)
	if got := TOTP(secret, 1); got != "287082" {
		t.Fatalf("RFC6238 truncation: %s", got)
	}
	step, ok := VerifyTOTP(secret, "287082", now, 0)
	if !ok || step != 1 {
		t.Fatal("valid code rejected")
	}
	if _, ok = VerifyTOTP(secret, "287082", now, 1); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok = VerifyTOTP(secret, "287082", now.Add(2*time.Minute), 0); ok {
		t.Fatal("expired code accepted")
	}
}
