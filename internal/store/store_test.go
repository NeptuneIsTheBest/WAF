package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
	"waf/internal/config"
	"waf/internal/secure"
)

func testStore(t *testing.T) (*Store, config.Bootstrap) {
	t.Helper()
	b := config.DefaultBootstrap()
	b.DataDir = t.TempDir()
	b.MasterKeyFile = filepath.Join(b.DataDir, "master.key")
	if err := secure.CreateKey(b.MasterKeyFile); err != nil {
		t.Fatal(err)
	}
	s, err := Open(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, b
}
func TestRevisionCASAndEncryptedSecrets(t *testing.T) {
	s, b := testStore(t)
	d, err := s.Draft()
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.SaveDraft(d, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveDraft(d, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale write succeeded")
	}
	rev, err := s.Publish(next, "test", "4.25.0")
	if err != nil || rev.ID != 1 {
		t.Fatal(err)
	}
	if _, err = s.Publish(next, "stale", "4.25.0"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale publish succeeded")
	}
	token := []byte("sensitive-cloudflare-token-unique")
	if err = s.PutSecret("cloudflare", token, "test"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Secret("cloudflare")
	if err != nil || !bytes.Equal(got, token) {
		t.Fatal(err)
	}
	s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	raw, err := os.ReadFile(filepath.Join(b.DataDir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, token) {
		t.Fatal("credential persisted in plaintext")
	}
}
func TestMFASessionsRecoveryAndLastAdmin(t *testing.T) {
	s, _ := testStore(t)
	u, secret, codes, err := s.CreateUser("admin", "a strong test password", "admin", "test")
	if err != nil {
		t.Fatal(err)
	}
	code := secure.TOTP(secret, time.Now().Unix()/30)
	if _, err = s.Authenticate("admin", "a strong test password", code, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate("admin", "a strong test password", code, false); !errors.Is(err, ErrAuth) {
		t.Fatal("TOTP replay")
	}
	if _, err = s.Authenticate("admin", "a strong test password", codes[0], false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authenticate("admin", "a strong test password", codes[0], false); !errors.Is(err, ErrAuth) {
		t.Fatal("recovery replay")
	}
	token, _, err := s.NewSession(u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(token); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateUser(u.ID, "viewer", false, "test"); err == nil {
		t.Fatal("last admin demoted")
	}
	if _, _, _, err = s.CreateUser("second", "another strong password", "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateUser(u.ID, "viewer", false, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Session(token); !errors.Is(err, ErrAuth) {
		t.Fatal("role change did not revoke session")
	}
}
func TestEventRetentionAndWriteFailure(t *testing.T) {
	s, _ := testStore(t)
	s.maxRows = 2
	for i := 0; i < 5; i++ {
		s.Record(Event{Action: "block", SiteID: "site", Path: "/safe", Message: "attack"})
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events, _ := s.Events(EventFilter{})
		if len(events) == 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.prune()
	events, err := s.Events(EventFilter{})
	if err != nil || len(events) != 2 {
		t.Fatalf("retention: %d %v", len(events), err)
	}
	s.EventsDB.Close()
	s.Record(Event{Action: "block"})
	deadline = time.Now().Add(3 * time.Second)
	for s.WriteErrors.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.WriteErrors.Load() == 0 || s.Dropped.Load() == 0 {
		t.Fatal("write failure was not surfaced")
	}
}

func TestLegacySecurityRejectedInDraftAndRevision(t *testing.T) {
	s, boot := testStore(t)
	legacy := `{"sites":[{"id":"old","managed":{"mode":"block"}}]}`
	if _, err := s.DB.Exec(`UPDATE draft SET body=? WHERE id=1`, legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Draft(); err == nil {
		t.Fatal("legacy draft silently loaded")
	}
	if _, err := s.DB.Exec(`INSERT INTO revisions(id,created,actor,crs_version,body) VALUES(1,?,?,?,?)`, now(), "test", "4.25.0", legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revision(1); err == nil {
		t.Fatal("legacy revision silently loaded")
	}
	s.Close()
	if reopened, err := Open(boot); err == nil {
		reopened.Close()
		t.Fatal("legacy backup or installation opened")
	}
}
