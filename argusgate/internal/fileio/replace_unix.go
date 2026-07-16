//go:build !windows

package fileio

import "os"

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}
