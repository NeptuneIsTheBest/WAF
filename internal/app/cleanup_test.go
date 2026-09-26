package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCrashBodyCleanup(t *testing.T) {
	dir := t.TempDir()
	if err := cleanBodyFiles(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"body-123", "body456", "crzmp789", "unrelated"} {
		if err := os.WriteFile(filepath.Join(dir, "tmp", name), []byte("private body"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanBodyFiles(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "tmp"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "unrelated" {
		t.Fatalf("cleanup: %v %v", entries, err)
	}
}
