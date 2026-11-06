//go:build windows

package content

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func acquirePinsFileLock(root string) (func(), error) {
	lockFile, err := os.OpenFile(filepath.Join(root, ".pins.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open content-store lock: %w", err)
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(lockFile.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock content store: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(lockFile.Fd()), 0, 1, 0, overlapped)
		_ = lockFile.Close()
	}, nil
}
