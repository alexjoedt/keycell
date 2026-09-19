package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexjoedt/keycell/internal/daemon"
	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/tty"
	"github.com/alexjoedt/keycell/internal/vault"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

// testDaemon is an in-process keycelld over a temporary socket with a
// vault directory initialized like `keycell init --no-passphrase`.
type testDaemon struct {
	socket   string
	dataDir  string
	identity []byte
	answers  []string
}

func (d *testDaemon) prompt() tty.ReadFunc {
	return func(string) ([]byte, error) {
		if len(d.answers) == 0 {
			return nil, tty.ErrNoTTY
		}
		a := d.answers[0]
		d.answers = d.answers[1:]
		return []byte(a), nil
	}
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
	return &testDaemon{socket: socket, dataDir: dataDir, identity: id}
}

func (d *testDaemon) unlock(t *testing.T, dur time.Duration) {
	t.Helper()
	c, err := keycell.ConnectSocket(context.Background(), d.socket)
	if err != nil {
		t.Fatal(err)
	}
	id := bytes.Clone(d.identity)
	if err := c.UnlockFor(context.Background(), id, dur); err != nil {
		t.Fatal(err)
	}
}

func (d *testDaemon) locked(t *testing.T) bool {
	t.Helper()
	c, err := keycell.ConnectSocket(context.Background(), d.socket)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st.Locked
}

// exec runs the CLI in-process with the daemon's socket and data dir in
// the environment and returns exit code, stdout and stderr. Passphrase
// prompts get the answers in order and fail like a missing TTY after.
func (d *testDaemon) exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return execCLI(t, d.socket, d.dataDir, d.prompt(), args...)
}

func execCLI(t *testing.T, socket, dataDir string, prompt tty.ReadFunc, args ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	code, stderr := execIO(t, socket, dataDir, strings.NewReader(""), &stdout, prompt, args...)
	return code, stdout.String(), stderr
}

// execIO is execCLI with stdin and stdout supplied by the test.
func execIO(t *testing.T, socket, dataDir string, stdin io.Reader, stdout io.Writer, prompt tty.ReadFunc, args ...string) (int, string) {
	t.Helper()
	env := map[string]string{
		"KEYCELL_SOCKET":   socket,
		"KEYCELL_DATA_DIR": dataDir,
		"XDG_CONFIG_HOME":  filepath.Join(dataDir, "xdg-config"),
	}
	var stderr bytes.Buffer
	code := run(context.Background(), append([]string{"keycell"}, args...),
		func(k string) string { return env[k] }, stdin, stdout, &stderr, prompt, nil)
	return code, stderr.String()
}

func TestStatus(t *testing.T) {
	d := startDaemon(t)

	code, out, errOut := d.exec(t, "status")
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"socket:   " + d.socket, "identity: UNENCRYPTED", "daemon:   locked"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}

	d.unlock(t, 0)
	_, out, _ = d.exec(t, "status")
	if !strings.Contains(out, "daemon:   unlocked, no auto-lock") {
		t.Errorf("stdout:\n%s", out)
	}

	d.unlock(t, 90*time.Minute)
	_, out, _ = d.exec(t, "status")
	if !strings.Contains(out, "daemon:   unlocked, locks in 1h30m") {
		t.Errorf("stdout:\n%s", out)
	}
}

func TestStatusSocketFlagBeatsEnv(t *testing.T) {
	d := startDaemon(t)
	code, out, _ := d.exec(t, "--socket", "/nonexistent/keycell.sock", "status")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"socket:   /nonexistent/keycell.sock", "daemon:   not running, run 'systemctl --user start keycell'"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestLock(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)

	if code, _, errOut := d.exec(t, "lock"); code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !d.locked(t) {
		t.Fatal("daemon still unlocked")
	}
	if code, _, _ := d.exec(t, "lock"); code != 0 {
		t.Fatalf("lock on locked daemon: exit %d", code)
	}
}

func TestExitCodes(t *testing.T) {
	d := startDaemon(t)
	tests := []struct {
		name string
		args []string
		code int
		err  string
	}{
		{"help", []string{"--help"}, 0, ""},
		{"unknown command", []string{"frobnicate"}, 2, `unknown command "frobnicate"`},
		{"unknown flag", []string{"--bogus"}, 2, "keycell: "},
		{"extra argument", []string{"lock", "now"}, 2, "lock takes no arguments"},
		{"not running", []string{"--socket", "/nonexistent/keycell.sock", "lock"}, 1,
			"keycell: daemon is not running, run 'systemctl --user start keycell'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := d.exec(t, tt.args...)
			if code != tt.code {
				t.Errorf("exit %d, want %d; stderr %q", code, tt.code, errOut)
			}
			if !strings.Contains(errOut, tt.err) {
				t.Errorf("stderr %q, want %q", errOut, tt.err)
			}
		})
	}
}

func TestExitErrorLocked(t *testing.T) {
	err := exitError(keycell.ErrLocked)
	if got := err.Error(); got != "keycell: daemon is locked, run 'keycell unlock'" {
		t.Errorf("got %q", got)
	}
}

func TestFormatRemaining(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{20 * time.Second, "<1m"},
		{12 * time.Minute, "12m"},
		{3*time.Hour + 12*time.Minute + 40*time.Second, "3h13m"},
		{8 * time.Hour, "8h0m"},
	}
	for _, tt := range tests {
		if got := formatRemaining(tt.d); got != tt.want {
			t.Errorf("%v: got %q, want %q", tt.d, got, tt.want)
		}
	}
}
