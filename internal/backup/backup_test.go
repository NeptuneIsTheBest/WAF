package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"waf/internal/config"
	"waf/internal/secure"
	"waf/internal/store"
)

func TestBackupRoundTripAndAuthentication(t *testing.T) {
	b := config.DefaultBootstrap()
	root := t.TempDir()
	b.DataDir = filepath.Join(root, "data")
	b.MasterKeyFile = filepath.Join(root, "master.key")
	if err := secure.CreateKey(b.MasterKeyFile); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.PutSecret("cloudflare", []byte("secret-marker"), "test"); err != nil {
		t.Fatal(err)
	}
	d, err := s.Draft()
	if err != nil {
		t.Fatal(err)
	}
	d.Bundle.Security.CustomRules = []config.CustomRule{{ID: "global", Enabled: true, Action: "log", Expression: "true", Scope: config.Scope{Mode: "all"}}}
	d, err = s.SaveDraft(d, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Publish(d, "test", "4.25.0"); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if err = Create(b, s, "backup test password", &encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes(), []byte("secret-marker")) {
		t.Fatal("backup plaintext")
	}
	dir, err := Extract(b, "backup test password", bytes.NewReader(encrypted.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if _, err = os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("master key was bundled")
	}
	restoredBoot := b
	restoredBoot.DataDir = dir
	restored, err := store.Open(restoredBoot)
	if err != nil {
		t.Fatal(err)
	}
	value, err := restored.Secret("cloudflare")
	restoredRevision, revisionErr := restored.Active()
	restored.Close()
	if revisionErr != nil || len(restoredRevision.Bundle.Security.CustomRules) != 1 || restoredRevision.Bundle.Security.CustomRules[0].ID != "global" {
		t.Fatalf("global security lost in backup: %+v %v", restoredRevision, revisionErr)
	}
	if err != nil || string(value) != "secret-marker" {
		t.Fatal(err)
	}
	if _, err = Extract(b, "wrong password", bytes.NewReader(encrypted.Bytes())); err == nil {
		t.Fatal("wrong backup password accepted")
	}
	truncated := encrypted.Bytes()[:encrypted.Len()-8]
	if _, err = Extract(b, "backup test password", bytes.NewReader(truncated)); err == nil {
		t.Fatal("truncated backup accepted")
	}
}
