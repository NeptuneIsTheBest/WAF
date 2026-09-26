package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"waf/internal/config"
	"waf/internal/policy"
	"waf/internal/secure"
	"waf/internal/store"
)

type Manifest struct {
	Format               int    `json:"format"`
	Created              string `json:"created"`
	CRSVersion           string `json:"crs_version"`
	MasterKeyFingerprint string `json:"master_key_fingerprint"`
}

func Create(boot config.Bootstrap, s *store.Store, password string, out io.Writer) error {
	if len(password) < 12 || len(password) > 256 {
		return errors.New("backup password must be 12-256 bytes")
	}
	tmp, e := os.MkdirTemp(boot.DataDir, "backup-snapshot-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = s.Snapshot(tmp); e != nil {
		return e
	}
	manifest := Manifest{Format: 1, Created: time.Now().UTC().Format(time.RFC3339), CRSVersion: policy.CRSVersion, MasterKeyFingerprint: secure.Digest(string(s.Key()))}
	b, _ := json.Marshal(manifest)
	if e = os.WriteFile(filepath.Join(tmp, "manifest.json"), b, 0600); e != nil {
		return e
	}
	if e = snapshotCertificates(filepath.Join(boot.DataDir, "certificates"), filepath.Join(tmp, "certificates")); e != nil {
		return e
	}
	recipient, e := age.NewScryptRecipient(password)
	if e != nil {
		return e
	}
	encrypted, e := age.Encrypt(out, recipient)
	if e != nil {
		return e
	}
	gz := gzip.NewWriter(encrypted)
	tw := tar.NewWriter(gz)
	walkErr := filepath.WalkDir(tmp, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("non-regular file in backup")
		}
		rel, err := filepath.Rel(tmp, p)
		if err != nil {
			return err
		}
		h := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0600, Size: info.Size(), ModTime: info.ModTime()}
		if err = tw.WriteHeader(h); err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		f.Close()
		return copyErr
	})
	e1 := tw.Close()
	e2 := gz.Close()
	e3 := encrypted.Close()
	return errors.Join(walkErr, e1, e2, e3)
}
func snapshotCertificates(src, dst string) error {
	if _, e := os.Stat(src); os.IsNotExist(e) {
		return nil
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel == "locks" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0700)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return errors.New("invalid certificate storage file")
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".crt") {
			keyPath := strings.TrimSuffix(p, ".crt") + ".key"
			key, e := os.ReadFile(keyPath)
			if e != nil {
				return e
			}
			if _, e = tls.X509KeyPair(data, key); e != nil {
				return fmt.Errorf("certificate rotation in progress; retry backup: %w", e)
			}
			if e = os.WriteFile(filepath.Join(dst, strings.TrimSuffix(rel, ".crt")+".key"), key, 0600); e != nil {
				return e
			}
		}
		if strings.HasSuffix(p, ".key") {
			if _, e := os.Stat(filepath.Join(dst, rel)); e == nil {
				return nil
			}
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0600)
	})
}

// Extract verifies the encrypted stream, file boundaries and original master key before use.
// The caller must hold the process lock and swap the returned directory while the service is stopped.
func Extract(boot config.Bootstrap, password string, input io.Reader) (dir string, err error) {
	key, e := secure.LoadKey(boot.MasterKeyFile)
	if e != nil {
		return "", e
	}
	identity, e := age.NewScryptIdentity(password)
	if e != nil {
		return "", e
	}
	identity.SetMaxWorkFactor(18)
	decrypted, e := age.Decrypt(input, identity)
	if e != nil {
		return "", e
	}
	gz, e := gzip.NewReader(decrypted)
	if e != nil {
		return "", e
	}
	defer gz.Close()
	dir, e = os.MkdirTemp(filepath.Dir(boot.DataDir), "waf-restore-")
	if e != nil {
		return "", e
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	limited := &io.LimitedReader{R: gz, N: (4 << 30) + 1}
	tr := tar.NewReader(limited)
	var total int64
	seen := map[string]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return dir, e
		}
		name := filepath.ToSlash(h.Name)
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, "../") || seen[name] || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 2<<30 {
			return dir, errors.New("unsafe backup archive")
		}
		if name != "config.db" && name != "events.db" && name != "manifest.json" && !strings.HasPrefix(name, "certificates/") {
			return dir, errors.New("unexpected backup file")
		}
		seen[name] = true
		total += h.Size
		if total > 3<<30 {
			return dir, errors.New("backup exceeds 3 GiB extraction limit")
		}
		p := filepath.Join(dir, filepath.FromSlash(name))
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return dir, e
		}
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return dir, e
		}
		_, copyErr := io.CopyN(f, tr, h.Size)
		closeErr := f.Close()
		if e = errors.Join(copyErr, closeErr); e != nil {
			return dir, e
		}
	}
	// Consume the rest to verify gzip checksum and the age final authentication tag.
	if _, e = io.Copy(io.Discard, limited); e != nil {
		return dir, e
	}
	if limited.N == 0 {
		return dir, errors.New("decompressed archive exceeds 4 GiB")
	}
	var tail [1]byte
	if n, tailErr := decrypted.Read(tail[:]); n != 0 || tailErr != io.EOF {
		return dir, errors.New("invalid or unauthenticated archive tail")
	}
	b, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		return dir, e
	}
	var m Manifest
	if e = json.Unmarshal(b, &m); e != nil {
		return dir, e
	}
	if m.Format != 1 || !secure.Equal(m.MasterKeyFingerprint, secure.Digest(string(key))) || !seen["config.db"] || !seen["events.db"] {
		return dir, errors.New("backup format or master key does not match")
	}
	return dir, nil
}
