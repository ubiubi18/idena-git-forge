//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package content

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func acquirePinsFileLock(root string) (func(), error) {
	lockFile, err := os.OpenFile(filepath.Join(root, ".pins.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open content-store lock: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock content store: %w", err)
	}
	return func() {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		_ = lockFile.Close()
	}, nil
}
