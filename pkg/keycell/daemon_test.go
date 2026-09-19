package keycell

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/alexjoedt/keycell/internal/daemon"
	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/vault"
)

// testDaemon is an in-process keycelld over a temporary socket with a
// fresh vault. identity is the raw age secret key that opens the vault.
type testDaemon struct {
	socket   string
	dataDir  string
	identity []byte
}

func startDaemon(t *testing.T) *testDaemon {
	t.Helper()
	d, stop, err := newTestDaemon(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("daemon: %v", err)
		}
	})
	return d
}

// newTestDaemon serves over sockDir/keycell.sock with a fresh vault in
// dataDir; stop shuts it down and reports Serve's error.
func newTestDaemon(dataDir, sockDir string) (*testDaemon, func() error, error) {
	enc, err := identity.Generate()
	if err != nil {
		return nil, nil, err
	}
	id, err := identity.Parse(enc)
	if err != nil {
		return nil, nil, err
	}
	if err := vault.Write(filepath.Join(dataDir, vault.File), id, vault.New()); err != nil {
		return nil, nil, err
	}

	socket := filepath.Join(sockDir, "keycell.sock")
	ln, err := daemon.Listen(socket)
	if err != nil {
		return nil, nil, err
	}
	log := slog.New(slog.DiscardHandler)
	session := daemon.NewSession(log, 0)
	store := daemon.NewStore(filepath.Join(dataDir, vault.File), session, log)
	srv := daemon.NewServer(session, store, log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	stop := func() error {
		cancel()
		return <-done
	}
	return &testDaemon{socket: socket, dataDir: dataDir, identity: enc}, stop, nil
}

func (d *testDaemon) client(t *testing.T) *Client {
	t.Helper()
	c, err := ConnectSocket(context.Background(), d.socket)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// unlock opens the session with the daemon's identity.
func (d *testDaemon) unlock(t *testing.T, c *Client) {
	t.Helper()
	if err := c.Unlock(context.Background(), bytes.Clone(d.identity)); err != nil {
		t.Fatal(err)
	}
}
