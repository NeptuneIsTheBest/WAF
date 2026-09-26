package app

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func Lock(dataDir string) (func(), error) {
	if e := os.MkdirAll(dataDir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(dataDir, ".process.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("WAF is running or another local operation holds the data lock")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
