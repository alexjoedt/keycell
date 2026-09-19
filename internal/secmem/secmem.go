//go:build linux

// Package secmem holds the few bytes the daemon must keep in plaintext
// (the vault identity) outside the Go heap: in a private anonymous
// mapping that is locked against swap and excluded from core dumps. It
// also hardens the process against ptrace and core dumps (ADR 0005,
// .agent/docs/research/secmem-go.md).
package secmem

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// DebugEnv, when set to "1", makes Harden a no-op so a debugger can
// attach. Never set it in production.
const DebugEnv = "KEYCELL_DEBUG_DUMPABLE"

// ErrDebugDumpable is returned by Harden when DebugEnv disabled it. The
// process keeps running; the caller decides how loudly to warn.
var ErrDebugDumpable = errors.New("secmem: hardening skipped, " + DebugEnv + "=1")

// Buffer is a page-aligned region outside the Go heap. It is not safe
// for concurrent use.
type Buffer struct {
	mem  []byte
	size int
}

// New maps, locks and marks non-dumpable a region of at least size bytes.
// A failed mlock (RLIMIT_MEMLOCK, containers) is an error, not a panic;
// nothing stays mapped when New fails.
func New(size int) (*Buffer, error) {
	if size <= 0 {
		return nil, fmt.Errorf("secmem: size %d must be positive", size)
	}
	page := unix.Getpagesize()
	n := (size + page - 1) / page * page
	mem, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("secmem: mmap %d bytes: %w", n, err)
	}
	if err := unix.Mlock(mem); err != nil {
		_ = unix.Munmap(mem)
		return nil, fmt.Errorf("secmem: mlock: %w", err)
	}
	if err := unix.Madvise(mem, unix.MADV_DONTDUMP); err != nil {
		_ = unix.Munlock(mem)
		_ = unix.Munmap(mem)
		return nil, fmt.Errorf("secmem: madvise: %w", err)
	}
	return &Buffer{mem: mem, size: size}, nil
}

// Bytes returns the usable region, or nil after Destroy. The slice aliases
// the mapping: do not retain it past Destroy.
func (b *Buffer) Bytes() []byte {
	if b.mem == nil {
		return nil
	}
	return b.mem[:b.size]
}

// Destroy zeroes, unlocks and unmaps the region. Calling it again is a
// no-op.
func (b *Buffer) Destroy() {
	if b.mem == nil {
		return
	}
	b.wipe()
	_ = unix.Munlock(b.mem)
	_ = unix.Munmap(b.mem)
	b.mem = nil
}

func (b *Buffer) wipe() {
	clear(b.mem)
	runtime.KeepAlive(b.mem)
}

// Harden makes the process non-dumpable (no core dumps, no ptrace attach
// by non-root) and sets the soft RLIMIT_CORE to 0. Only the soft limit
// changes so children started via exec can raise it again. With DebugEnv
// set to "1" it does nothing and returns ErrDebugDumpable.
func Harden() error {
	if os.Getenv(DebugEnv) == "1" {
		return ErrDebugDumpable
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("secmem: prctl PR_SET_DUMPABLE: %w", err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return fmt.Errorf("secmem: getrlimit RLIMIT_CORE: %w", err)
	}
	lim.Cur = 0
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return fmt.Errorf("secmem: setrlimit RLIMIT_CORE: %w", err)
	}
	return nil
}
