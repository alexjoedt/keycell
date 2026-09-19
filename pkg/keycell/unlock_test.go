package keycell

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexjoedt/keycell/internal/identity"
)

func TestUnlockWipesIdentity(t *testing.T) {
	ctx := context.Background()
	d := startDaemon(t)
	c := d.client(t)

	id := bytes.Clone(d.identity)
	if err := c.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id, make([]byte, len(id))) {
		t.Fatal("identity not zeroed after Unlock")
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Locked || !st.LocksAt.IsZero() {
		t.Fatalf("Status after Unlock = %+v", st)
	}
}

func TestUnlockFor(t *testing.T) {
	ctx := context.Background()
	d := startDaemon(t)
	c := d.client(t)

	if err := c.UnlockFor(ctx, bytes.Clone(d.identity), time.Second); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Locked || st.LocksAt.IsZero() || time.Until(st.LocksAt) > 2*time.Second {
		t.Fatalf("Status after UnlockFor = %+v", st)
	}

	if err := c.UnlockFor(ctx, bytes.Clone(d.identity), 0); err != nil {
		t.Fatal(err)
	}
	if err := c.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.UnlockFor(ctx, bytes.Clone(d.identity), 0); err != nil {
		t.Fatal(err)
	}
	st, err = c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Locked || !st.LocksAt.IsZero() {
		t.Fatalf("Status after UnlockFor(0) = %+v", st)
	}
}

func TestUnlockWrongIdentity(t *testing.T) {
	ctx := context.Background()
	d := startDaemon(t)
	c := d.client(t)

	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Unlock(ctx, other); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Unlock wrong identity = %v, want ErrInvalidArgument", err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Locked {
		t.Fatal("daemon unlocked after rejected identity")
	}
}

func TestLoadIdentityPlain(t *testing.T) {
	d := startDaemon(t)
	path := filepath.Join(d.dataDir, identity.PlainFile)
	if err := identity.WritePlain(path, bytes.Clone(d.identity)); err != nil {
		t.Fatal(err)
	}

	id, err := LoadIdentity(path, []byte("ignored"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(id), bytes.TrimSpace(d.identity)) {
		t.Fatal("loaded identity differs")
	}
	c := d.client(t)
	if err := c.Unlock(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	_, err = LoadIdentity(filepath.Join(d.dataDir, "missing", identity.PlainFile), nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file = %v, want ErrNotFound", err)
	}
	_, err = LoadIdentity(filepath.Join(d.dataDir, "vault.age"), nil)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unknown file name = %v, want ErrInvalidArgument", err)
	}
}

func TestLoadIdentityEncrypted(t *testing.T) {
	d := startDaemon(t)
	path := filepath.Join(d.dataDir, identity.EncryptedFile)
	if err := identity.WriteEncrypted(path, bytes.Clone(d.identity), []byte("correct horse")); err != nil {
		t.Fatal(err)
	}

	pass := []byte("correct horse")
	id, err := LoadIdentity(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Fatal("passphrase not zeroed")
	}
	c := d.client(t)
	if err := c.Unlock(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadIdentity(path, []byte("wrong")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("wrong passphrase = %v, want ErrInvalidArgument", err)
	}
	if _, err := LoadIdentity(path, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty passphrase = %v, want ErrInvalidArgument", err)
	}
}
