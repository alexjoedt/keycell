package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/vault"
)

func newTestStore(t *testing.T) (*Store, *Session, []byte) {
	t.Helper()
	enc := newIdentity(t)
	id, err := identity.Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), vault.File)
	if err := vault.Write(path, id, vault.New()); err != nil {
		t.Fatal(err)
	}
	s, _ := newTestSession(t, 0)
	st := NewStore(path, s, slog.New(slog.DiscardHandler))
	st.now = func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) }
	return st, s, enc
}

func unlock(t *testing.T, s *Session, enc []byte) {
	t.Helper()
	if err := s.Unlock(bytes.Clone(enc), nil); err != nil {
		t.Fatal(err)
	}
}

func TestStoreGetDelete(t *testing.T) {
	st, s, enc := newTestStore(t)
	unlock(t, s, enc)
	attrs := map[string]string{"host": "github.com"}

	if err := st.Store("git/github.com", "git-credential", attrs, []byte("ghp_1")); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("git/github.com")
	if err != nil {
		t.Fatal(err)
	}
	created := st.now()
	if got.Name != "git/github.com" || got.Kind != "git-credential" || got.Attributes["host"] != "github.com" || string(got.Value) != "ghp_1" || !got.Created.Equal(created) || !got.Updated.Equal(created) {
		t.Fatalf("got %+v", got)
	}

	later := created.Add(time.Hour)
	st.now = func() time.Time { return later }
	if err := st.Store("git/github.com", "git-credential", nil, []byte("ghp_2")); err != nil {
		t.Fatal(err)
	}
	got, err = st.Get("git/github.com")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value) != "ghp_2" || got.Attributes != nil || !got.Created.Equal(created) || !got.Updated.Equal(later) {
		t.Fatalf("upsert: got %+v", got)
	}

	if err := st.Delete("git/github.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("git/github.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	if err := st.Delete("git/github.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestList(t *testing.T) {
	st, s, enc := newTestStore(t)
	unlock(t, s, enc)
	seed := []struct {
		name, kind string
		attrs      map[string]string
	}{
		{"git/github.com", "git-credential", map[string]string{"host": "github.com", "username": "alex"}},
		{"git/gitlab.com", "git-credential", map[string]string{"host": "gitlab.com"}},
		{"docker/ghcr.io", "docker-registry", map[string]string{"server": "https://ghcr.io"}},
		{"api/openai", "token", nil},
	}
	for _, x := range seed {
		if err := st.Store(x.name, x.kind, x.attrs, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name string
		f    Filter
		want []string
	}{
		{"all sorted", Filter{}, []string{"api/openai", "docker/ghcr.io", "git/github.com", "git/gitlab.com"}},
		{"kind", Filter{Kind: "git-credential"}, []string{"git/github.com", "git/gitlab.com"}},
		{"prefix", Filter{Prefix: "git/"}, []string{"git/github.com", "git/gitlab.com"}},
		{"attributes subset", Filter{Attributes: map[string]string{"host": "github.com"}}, []string{"git/github.com"}},
		{"attributes all must match", Filter{Attributes: map[string]string{"host": "github.com", "username": "bob"}}, nil},
		{"combined", Filter{Kind: "git-credential", Prefix: "git/gitl"}, []string{"git/gitlab.com"}},
		{"none", Filter{Kind: "ssh-key"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := st.List(tt.f)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(got))
			for _, s := range got {
				if s.Value != nil {
					t.Fatal("list returned a value")
				}
				names = append(names, s.Name)
			}
			if len(names) != len(tt.want) {
				t.Fatalf("got %v, want %v", names, tt.want)
			}
			for i := range names {
				if names[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", names, tt.want)
				}
			}
		})
	}
	if _, err := st.List(Filter{Kind: "Bad Kind"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("got %v, want ErrInvalidArgument", err)
	}
}

func TestInvalidArguments(t *testing.T) {
	st, s, enc := newTestStore(t)
	unlock(t, s, enc)
	tests := []struct {
		name string
		call func() error
		rule error
	}{
		{"empty name", func() error { return st.Store("", "k", nil, []byte("v")) }, vault.ErrEmptyName},
		{"bad kind", func() error { return st.Store("n", "Kind", nil, []byte("v")) }, vault.ErrInvalidKind},
		{"bad attribute key", func() error { return st.Store("n", "k", map[string]string{"Host": "x"}, []byte("v")) }, vault.ErrInvalidAttrKey},
		{"value too large", func() error { return st.Store("n", "k", nil, make([]byte, vault.MaxValueLen+1)) }, vault.ErrValueTooLarge},
		{"get control char", func() error { _, err := st.Get("a\nb"); return err }, vault.ErrControlChar},
		{"delete empty", func() error { return st.Delete("") }, vault.ErrEmptyName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if !errors.Is(err, ErrInvalidArgument) || !errors.Is(err, tt.rule) {
				t.Fatalf("got %v, want ErrInvalidArgument wrapping %v", err, tt.rule)
			}
		})
	}
	if got, _ := st.List(Filter{}); len(got) != 0 {
		t.Fatalf("rejected store wrote %d secrets", len(got))
	}
}

func TestLockedTouchesNothing(t *testing.T) {
	st, _, _ := newTestStore(t)
	if err := os.Remove(st.path); err != nil {
		t.Fatal(err)
	}
	calls := []func() error{
		func() error { _, err := st.Get("n"); return err },
		func() error { _, err := st.List(Filter{}); return err },
		func() error { return st.Store("n", "k", nil, []byte("v")) },
		func() error { return st.Delete("n") },
	}
	for i, call := range calls {
		if err := call(); !errors.Is(err, ErrLocked) {
			t.Fatalf("call %d: got %v, want ErrLocked", i, err)
		}
	}
	if _, err := os.Stat(st.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("locked operation touched the vault file")
	}
}

func TestReadErrorIsNotSentinel(t *testing.T) {
	st, s, enc := newTestStore(t)
	unlock(t, s, enc)
	if err := os.WriteFile(st.path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := st.Get("n")
	if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrLocked) {
		t.Fatalf("got %v, want an internal error", err)
	}
}

func TestWipe(t *testing.T) {
	st, s, enc := newTestStore(t)
	unlock(t, s, enc)
	var wiped int
	var leftover [][]byte
	wipeVault = func(v *vault.Vault, b []byte) {
		for _, sec := range v.Secrets {
			leftover = append(leftover, sec.Value)
		}
		vault.Wipe(v, b)
		wiped++
	}
	t.Cleanup(func() { wipeVault = vault.Wipe })

	value := []byte("ghp_secret")
	if err := st.Store("n", "k", nil, value); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("stored value not consumed")
	}
	got, err := st.Get("n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.List(Filter{}); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete("n"); err != nil {
		t.Fatal(err)
	}
	if wiped != 4 {
		t.Fatalf("Wipe called %d times, want 4", wiped)
	}
	for _, b := range leftover {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("vault plaintext value survived Wipe")
		}
	}
	if string(got.Value) != "ghp_secret" {
		t.Fatal("returned copy was wiped with the vault")
	}
}
