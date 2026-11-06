//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package content

import "errors"

func acquirePinsFileLock(string) (func(), error) {
	return nil, errors.New("content-store cross-process locking is unsupported on this platform")
}
