package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func Digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func LoadKey(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("master key permissions must be 0600 or stricter")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("master key must contain exactly 32 random bytes")
	}
	return b, nil
}
func CreateKey(path string) error {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}
func Seal(key []byte, purpose string, value []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, value, []byte(purpose)), nil
}
func Open(key []byte, purpose string, value []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(value) < a.NonceSize() {
		return nil, errors.New("invalid ciphertext")
	}
	return a.Open(nil, value[:a.NonceSize()], value[a.NonceSize():], []byte(purpose))
}
func Sign(key []byte, purpose, payload string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(purpose))
	m.Write([]byte{0})
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func Password(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", errors.New("password must be 12-256 bytes")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}
func VerifyPassword(encoded, password string) bool {
	if len(password) > 256 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=2" {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[4])
	if e != nil || len(salt) != 16 {
		return false
	}
	hash, e := base64.RawStdEncoding.DecodeString(parts[5])
	if e != nil || len(hash) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return subtle.ConstantTimeCompare(hash, got) == 1
}
func TOTPSecret() string {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
func TOTP(secret string, step int64) string {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(b)
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 15
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	if _, e := strconv.Atoi(code); e != nil {
		return 0, false
	}
	for _, delta := range []int64{0, -1, 1} {
		step := now.Unix()/30 + delta
		if step > lastStep && Equal(TOTP(secret, step), code) {
			return step, true
		}
	}
	return 0, false
}
