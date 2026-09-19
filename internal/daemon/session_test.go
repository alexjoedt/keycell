package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/alexjoedt/keycell/internal/identity"
)

// fakeClock replaces the timer: fire runs the pending auto-lock callback.
type fakeClock struct {
	now     time.Time
	pending func()
	delay   time.Duration
	last    *fakeTimer
}

type fakeTimer struct{ stopped bool }

func (t *fakeTimer) Stop() bool { t.stopped = true; return true }

func (c *fakeClock) after(d time.Duration, f func()) timer {
	c.pending, c.delay, c.last = f, d, &fakeTimer{}
	return c.last
}

func (c *fakeClock) fire() {
	c.now = c.now.Add(c.delay)
	c.pending()
}

func newTestSession(t *testing.T, defaultFor time.Duration) (*Session, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)}
	s := NewSession(slog.New(slog.DiscardHandler), defaultFor)
	s.now = func() time.Time { return clock.now }
	s.afterFunc = clock.after
	return s, clock
}

func newIdentity(t *testing.T) []byte {
	t.Helper()
	enc, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestUnlockLock(t *testing.T) {
	s, _ := newTestSession(t, 0)
	enc := newIdentity(t)
	want := append([]byte(nil), enc...)

	if err := s.Unlock(enc, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, make([]byte, len(enc))) {
		t.Fatal("input identity not zeroed")
	}
	buf := s.buf
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatal("locked buffer does not hold the identity")
	}
	if locked, at := s.Status(); locked || !at.IsZero() {
		t.Fatalf("status locked=%v locksAt=%v", locked, at)
	}
	err := s.With(func(id *age.X25519Identity) error {
		if id.String() != string(want) {
			t.Fatal("With got a different identity")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	s.Lock(LockManual)
	if buf.Bytes() != nil || s.buf != nil || s.id != nil {
		t.Fatal("buffer not destroyed after Lock")
	}
	if locked, _ := s.Status(); !locked {
		t.Fatal("not locked")
	}
	if err := s.With(func(*age.X25519Identity) error { return nil }); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v, want ErrLocked", err)
	}
	s.Lock(LockManual)
}

func TestUnlockRejectsMalformed(t *testing.T) {
	s, _ := newTestSession(t, 0)
	in := []byte("not-a-key")
	if err := s.Unlock(in, nil); !errors.Is(err, identity.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
	if !bytes.Equal(in, make([]byte, len(in))) {
		t.Fatal("rejected input not zeroed")
	}
	if locked, _ := s.Status(); !locked {
		t.Fatal("unlocked by malformed identity")
	}
}

func TestLockWaitsForRequest(t *testing.T) {
	s, _ := newTestSession(t, 0)
	if err := s.Unlock(newIdentity(t), nil); err != nil {
		t.Fatal(err)
	}
	inside, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = s.With(func(id *age.X25519Identity) error {
			close(inside)
			<-release
			if id == nil || s.id == nil {
				t.Error("identity dropped during request")
			}
			return nil
		})
	})
	<-inside
	locked := make(chan struct{})
	go func() { s.Lock(LockManual); close(locked) }()
	select {
	case <-locked:
		t.Fatal("Lock returned while a request was running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-locked
	wg.Wait()
	if l, _ := s.Status(); !l {
		t.Fatal("not locked after request finished")
	}
}

func TestAutoLock(t *testing.T) {
	t.Run("default duration", func(t *testing.T) {
		s, clock := newTestSession(t, 8*time.Hour)
		if err := s.Unlock(newIdentity(t), nil); err != nil {
			t.Fatal(err)
		}
		_, at := s.Status()
		if want := clock.now.Add(8 * time.Hour); !at.Equal(want) || clock.delay != 8*time.Hour {
			t.Fatalf("locks_at %v delay %v", at, clock.delay)
		}
		if err := s.With(func(*age.X25519Identity) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, after := s.Status(); !after.Equal(at) {
			t.Fatal("request extended the auto-lock deadline")
		}
		clock.fire()
		if locked, at := s.Status(); !locked || !at.IsZero() {
			t.Fatalf("locked=%v locksAt=%v after timer", locked, at)
		}
	})
	t.Run("explicit for", func(t *testing.T) {
		s, clock := newTestSession(t, 8*time.Hour)
		d := time.Hour
		if err := s.Unlock(newIdentity(t), &d); err != nil {
			t.Fatal(err)
		}
		if clock.delay != time.Hour {
			t.Fatalf("delay %v", clock.delay)
		}
	})
	t.Run("zero disables", func(t *testing.T) {
		s, clock := newTestSession(t, 8*time.Hour)
		d := time.Duration(0)
		if err := s.Unlock(newIdentity(t), &d); err != nil {
			t.Fatal(err)
		}
		if _, at := s.Status(); !at.IsZero() || clock.pending != nil {
			t.Fatal("auto-lock armed although for=0")
		}
	})
	t.Run("re-unlock replaces timer", func(t *testing.T) {
		s, clock := newTestSession(t, time.Hour)
		if err := s.Unlock(newIdentity(t), nil); err != nil {
			t.Fatal(err)
		}
		stale, old := clock.pending, clock.last
		if err := s.Unlock(newIdentity(t), nil); err != nil {
			t.Fatal(err)
		}
		if !old.stopped {
			t.Fatal("old timer not stopped")
		}
		stale()
		if locked, _ := s.Status(); locked {
			t.Fatal("stale timer locked the new session")
		}
		clock.fire()
		if locked, _ := s.Status(); !locked {
			t.Fatal("new timer did not lock")
		}
	})
	t.Run("manual lock stops timer", func(t *testing.T) {
		s, clock := newTestSession(t, time.Hour)
		if err := s.Unlock(newIdentity(t), nil); err != nil {
			t.Fatal(err)
		}
		s.Lock(LockManual)
		if !clock.last.stopped {
			t.Fatal("timer still armed after Lock")
		}
	})
}
