// Package daemon holds the state and request handling of keycelld. The
// session is the lock/unlock state machine (ADR 0005, 0007, wayfinder
// ticket 04); socket serving and vault operations live in sibling files.
package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/secmem"
)

// ErrLocked is returned by With while no identity is held.
var ErrLocked = errors.New("daemon: locked")

// Lock reasons, logged on every transition to locked.
const (
	LockManual   = "manual"
	LockAuto     = "auto"
	LockShutdown = "shutdown"
)

// timer is the subset of *time.Timer the session uses; tests inject
// their own to fire auto-lock deterministically.
type timer interface{ Stop() bool }

// Session is the daemon's lock state. Requests run under With and hold
// a read lock; Unlock and Lock take the write lock, so a lock waits for
// in-flight requests and never interrupts them.
type Session struct {
	log        *slog.Logger
	defaultFor time.Duration
	now        func() time.Time
	afterFunc  func(time.Duration, func()) timer

	mu      sync.RWMutex
	buf     *secmem.Buffer
	id      *age.X25519Identity
	timer   timer
	locksAt time.Time
	gen     uint64
}

// NewSession returns a locked session. defaultFor is the auto-lock
// duration used when Unlock is called without one; 0 disables it.
func NewSession(log *slog.Logger, defaultFor time.Duration) *Session {
	return &Session{
		log:        log,
		defaultFor: defaultFor,
		now:        time.Now,
		afterFunc:  func(d time.Duration, f func()) timer { return time.AfterFunc(d, f) },
	}
}

// Unlock parses encoded (an "AGE-SECRET-KEY-1..." line), moves it into
// locked memory and arms auto-lock. lockAfter nil means the configured
// default, 0 disables auto-lock for this session. The input is zeroed
// whether or not it parses. Unlocking an unlocked session replaces the
// identity and restarts the timer.
func (s *Session) Unlock(encoded []byte, lockAfter *time.Duration) error {
	defer wipe(encoded)
	id, err := identity.Parse(encoded)
	if err != nil {
		return err
	}
	buf, err := secmem.New(len(encoded))
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	copy(buf.Bytes(), encoded)

	d := s.defaultFor
	if lockAfter != nil {
		d = *lockAfter
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop()
	s.buf, s.id = buf, id
	s.gen++
	if d > 0 {
		gen := s.gen
		s.locksAt = s.now().Add(d)
		s.timer = s.afterFunc(d, func() { s.autoLock(gen) })
		s.log.Info("unlocked", "locks_at", s.locksAt)
	} else {
		s.log.Info("unlocked", "auto_lock", "off")
	}
	return nil
}

// Lock waits for running requests, destroys the identity and stops the
// timer. Locking a locked session is a no-op.
func (s *Session) Lock(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf == nil {
		return
	}
	s.drop()
	s.log.Info("locked", "reason", reason)
}

// autoLock fires from the timer; gen guards against a timer that was
// replaced by a later Unlock but had already started running.
func (s *Session) autoLock(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buf == nil || s.gen != gen {
		return
	}
	s.drop()
	s.log.Info("locked", "reason", LockAuto)
}

// drop releases identity and timer; the caller holds the write lock.
func (s *Session) drop() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if s.buf != nil {
		s.buf.Destroy()
		s.buf = nil
	}
	s.id = nil
	s.locksAt = time.Time{}
}

// Status reports whether the session is locked and, while unlocked with
// auto-lock armed, when it locks; locksAt is zero otherwise.
func (s *Session) Status() (locked bool, locksAt time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.buf == nil, s.locksAt
}

// With runs fn with the identity under a read lock, so a concurrent Lock
// waits until fn returns. It returns ErrLocked while locked.
func (s *Session) With(fn func(id *age.X25519Identity) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.id == nil {
		return ErrLocked
	}
	return fn(s.id)
}

func wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
