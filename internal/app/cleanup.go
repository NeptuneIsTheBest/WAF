package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Run is entered with the data-directory process lock held. Only known request
// body artifacts are removed; a crash must not retain uploaded plaintext.
func cleanBodyFiles(dataDir string) error {
	dir := filepath.Join(dataDir, "tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && (strings.HasPrefix(entry.Name(), "body") || strings.HasPrefix(entry.Name(), "crzmp")) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return fmt.Errorf("remove stale request body: %w", err)
			}
		}
	}
	return nil
}
