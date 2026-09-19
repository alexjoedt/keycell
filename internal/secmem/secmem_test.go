//go:build linux

package secmem

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBufferLifecycle(t *testing.T) {
	b, err := New(32)
	if err != nil {
		t.Fatal(err)
	}
	mem := b.Bytes()
	if len(mem) != 32 || cap(mem) < unix.Getpagesize() {
		t.Fatalf("len %d cap %d", len(mem), cap(mem))
	}
	copy(mem, "AGE-SECRET-KEY-1................")

	b.wipe()
	if !bytes.Equal(mem, make([]byte, 32)) {
		t.Fatalf("not zeroed: %q", mem)
	}

	b.Destroy()
	if b.Bytes() != nil {
		t.Fatal("Bytes after Destroy is not nil")
	}
	b.Destroy()
}

func TestNewErrors(t *testing.T) {
	if _, err := New(0); err == nil {
		t.Fatal("size 0 accepted")
	}
	if os.Getuid() == 0 {
		t.Skip("root ignores RLIMIT_MEMLOCK")
	}
	var saved unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &saved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &saved) })
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: saved.Max}); err != nil {
		t.Fatal(err)
	}
	b, err := New(32)
	if err == nil {
		b.Destroy()
		t.Fatal("mlock succeeded with RLIMIT_MEMLOCK=0")
	}
	if !errors.Is(err, unix.ENOMEM) && !errors.Is(err, unix.EPERM) {
		t.Fatalf("got %v, want ENOMEM or EPERM", err)
	}
}

func TestHarden(t *testing.T) {
	t.Run("debug env skips", func(t *testing.T) {
		t.Setenv(DebugEnv, "1")
		if err := Harden(); !errors.Is(err, ErrDebugDumpable) {
			t.Fatalf("got %v, want ErrDebugDumpable", err)
		}
		if d, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); d != 1 {
			t.Fatalf("dumpable changed to %d", d)
		}
	})
	t.Run("sets dumpable and core limit", func(t *testing.T) {
		if err := Harden(); err != nil {
			t.Fatal(err)
		}
		d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || d != 0 {
			t.Fatalf("dumpable %d, %v", d, err)
		}
		var lim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil || lim.Cur != 0 {
			t.Fatalf("RLIMIT_CORE soft %d, %v", lim.Cur, err)
		}
	})
}
