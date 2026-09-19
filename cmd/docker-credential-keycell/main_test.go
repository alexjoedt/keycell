package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexjoedt/keycell/internal/daemon"
	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/vault"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

// testDaemon is an in-process keycelld over a temporary socket with a
// plain identity, unlocked unless a test locks it.
type testDaemon struct {
	socket   string
	identity []byte
}

func startDaemon(t *testing.T) *testDaemon {
	t.Helper()
	dataDir := t.TempDir()
	if err := identity.Init(dataDir, nil); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Load(dataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "keycell.sock")
	ln, err := daemon.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	session := daemon.NewSession(log, 0)
	store := daemon.NewStore(filepath.Join(dataDir, vault.File), session, log)
	srv := daemon.NewServer(session, store, log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("daemon: %v", err)
		}
	})
	d := &testDaemon{socket: socket, identity: id}
	d.unlock(t)
	return d
}

func (d *testDaemon) client(t *testing.T) *keycell.Client {
	t.Helper()
	c, err := keycell.ConnectSocket(context.Background(), d.socket)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (d *testDaemon) unlock(t *testing.T) {
	t.Helper()
	if err := d.client(t).Unlock(context.Background(), bytes.Clone(d.identity)); err != nil {
		t.Fatal(err)
	}
}

func (d *testDaemon) lock(t *testing.T) {
	t.Helper()
	if err := d.client(t).Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// store puts a docker-registry secret into the daemon directly.
func (d *testDaemon) store(t *testing.T, name, server, username, value string) {
	t.Helper()
	s := secret(name, map[string]string{"server": server, "username": username}, value)
	if err := d.client(t).Store(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// secret builds a docker-registry secret, or one of the given kind.
func secret(name string, attrs map[string]string, value string, kinds ...string) keycell.Secret {
	k := kind
	if len(kinds) > 0 {
		k = kinds[0]
	}
	return keycell.Secret{Name: name, Kind: k, Attributes: attrs, Value: keycell.NewValue([]byte(value))}
}

func execHelper(t *testing.T, socket, stdin string, args ...string) (int, string, string) {
	t.Helper()
	env := map[string]string{"KEYCELL_SOCKET": socket, "HOME": t.TempDir()}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), append([]string{prog}, args...),
		func(k string) string { return env[k] }, strings.NewReader(stdin), &stdout, &stderr, nil)
	return code, stdout.String(), stderr.String()
}

func expect(t *testing.T, code int, stdout, stderr string, wantCode int, wantOut, wantErr string) {
	t.Helper()
	if code != wantCode || stdout != wantOut || stderr != wantErr {
		t.Fatalf("got (%d, %q, %q), want (%d, %q, %q)", code, stdout, stderr, wantCode, wantOut, wantErr)
	}
}

func TestUsage(t *testing.T) {
	usage := "usage: docker-credential-keycell <get|store|erase|list>\n"
	for _, args := range [][]string{nil, {"login"}, {"get", "extra"}, {"GET"}} {
		code, out, errOut := execHelper(t, "", "", args...)
		expect(t, code, out, errOut, 1, "", usage)
	}
}

func TestHarden(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{prog, "list"}, func(string) string { return "" }, strings.NewReader(""), &stdout, &stderr, errFake)
	if code != 1 || stderr.String() != "docker-credential-keycell: hardening failed: fake\n" {
		t.Fatalf("got (%d, %q)", code, stderr.String())
	}
}

func TestNotRunning(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "none.sock")
	env := map[string]string{"KEYCELL_SOCKET": socket, "HOME": t.TempDir()}
	h := &helper{env: func(k string) string { return env[k] }}
	_, err := h.connect(context.Background())
	code, msg := exitOf(t, daemonError(err))
	if code != 1 || msg != "docker-credential-keycell: daemon is not running, run 'systemctl --user start keycell'" {
		t.Fatalf("got (%d, %q)", code, msg)
	}
}

func TestDaemonError(t *testing.T) {
	d := startDaemon(t)
	d.lock(t)
	_, err := d.client(t).List(context.Background(), keycell.Filter{})
	code, msg := exitOf(t, daemonError(err))
	if code != 1 || msg != "docker-credential-keycell: daemon is locked, run 'keycell unlock'" {
		t.Fatalf("got (%d, %q)", code, msg)
	}
	code, msg = exitOf(t, daemonError(&ambiguousError{names: []string{"a", "b"}}))
	if code != 1 || msg != "docker-credential-keycell: ambiguous match: a, b" {
		t.Fatalf("got (%d, %q)", code, msg)
	}
	if daemonError(nil) != nil {
		t.Fatal("nil error mapped")
	}
}

func exitOf(t *testing.T, err error) (int, string) {
	t.Helper()
	ec, ok := errors.AsType[*exitError](err)
	if !ok {
		t.Fatalf("err = %T %v, want *exitError", err, err)
	}
	return ec.code, ec.msg
}

var errFake = errors.New("fake")
