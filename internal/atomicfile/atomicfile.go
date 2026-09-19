// Package atomicfile writes a file so that readers see either the old or
// the new content, never a partial one: temp file in the same directory,
// fsync, rename, fsync of the directory.
package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Write replaces path with data. With backup, the previous file survives
// as path+".bak" (one generation). If anything fails before the rename,
// path is untouched and the temp file is removed.
func Write(path string, data []byte, perm fs.FileMode, backup bool) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("atomicfile: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	fail := func(step string, err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("atomicfile: %s %s: %w", step, path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail("chmod", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("write", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicfile: close %s: %w", path, err)
	}
	if backup {
		if err := os.Rename(path, path+".bak"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			os.Remove(tmpName)
			return fmt.Errorf("atomicfile: backup %s: %w", path, err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicfile: rename %s: %w", path, err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("atomicfile: open dir %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("atomicfile: sync dir %s: %w", dir, err)
	}
	return nil
}
