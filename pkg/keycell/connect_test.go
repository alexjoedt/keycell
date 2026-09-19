package keycell

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexjoedt/keycell/internal/config"
)

// isolateEnv points every config source at empty temp locations so the
// developer's own config.json and runtime dir stay out of the test.
func isolateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv(config.EnvConfig, "")
	t.Setenv(config.EnvSocket, "")
}

func TestConnectResolvesSocket(t *testing.T) {
	isolateEnv(t)
	d := startDaemon(t)
	ctx := context.Background()

	t.Setenv(config.EnvSocket, d.socket)
	c, err := Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Socket() != d.socket {
		t.Fatalf("Socket = %q, want %q", c.Socket(), d.socket)
	}

	t.Setenv(config.EnvSocket, "")
	cfgDir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "keycell")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"socket":"`+d.socket+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Socket() != d.socket {
		t.Fatalf("config.json: Socket = %q, want %q", c.Socket(), d.socket)
	}

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", filepath.Dir(d.socket))
	_, err = Connect(ctx)
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("runtime dir without daemon = %v, want ErrNotRunning", err)
	}
}

func TestConnectWithoutRuntimeDir(t *testing.T) {
	isolateEnv(t)
	_, err := Connect(context.Background())
	if !errors.Is(err, config.ErrNoRuntimeDir) {
		t.Fatalf("err = %v, want ErrNoRuntimeDir", err)
	}
	if errors.Is(err, ErrNotRunning) {
		t.Fatal("missing runtime dir reported as ErrNotRunning")
	}
}
