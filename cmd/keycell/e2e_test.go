package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alexjoedt/keycell/internal/identity"
)

// e2e drives the built keycell binary against a keycelld process. Every
// command runs in its own session (Setsid), so /dev/tty is never
// available and prompts fail the way they do under systemd or cron.
type e2e struct {
	t       *testing.T
	bin     string
	socket  string
	dataDir string
}

func buildBinaries(t *testing.T) (keycell, keycelld string) {
	t.Helper()
	dir := t.TempDir()
	for _, b := range []struct{ name, pkg string }{{"keycell", "."}, {"keycelld", "../keycelld"}} {
		out, err := exec.Command("go", "build", "-o", filepath.Join(dir, b.name), b.pkg).CombinedOutput()
		if err != nil {
			t.Skipf("go build %s: %v\n%s", b.name, err, out)
		}
	}
	return filepath.Join(dir, "keycell"), filepath.Join(dir, "keycelld")
}

// startDaemonProcess runs keycelld with temporary paths and returns
// once the socket accepts connections. The process is stopped with
// SIGTERM at cleanup unless the test stopped it already.
func startDaemonProcess(t *testing.T, bin, socket, dataDir string) *exec.Cmd {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Env = e2eEnv(socket, dataDir, "KEYCELL_AUTO_LOCK=0")
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", socket); err == nil {
			conn.Close()
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("keycelld did not listen on %s within 5s\n%s", socket, stderr.String())
	return nil
}

func e2eEnv(socket, dataDir string, extra ...string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dataDir,
		"XDG_CONFIG_HOME=" + filepath.Join(dataDir, "xdg-config"),
		"KEYCELL_SOCKET=" + socket,
		"KEYCELL_DATA_DIR=" + dataDir,
	}
	return append(env, extra...)
}

// run executes one keycell command detached from the terminal and
// returns exit code, stdout and stderr.
func (e *e2e) run(stdin string, args ...string) (int, string, string) {
	e.t.Helper()
	return e.runIn(e.dataDir, stdin, args...)
}

func (e *e2e) runIn(dataDir, stdin string, args ...string) (int, string, string) {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(e.bin, args...)
	cmd.Env = e2eEnv(e.socket, dataDir)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		e.t.Fatalf("%v: %v", args, err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

func (e *e2e) expect(code int, stdout, stderr string, args ...string) {
	e.t.Helper()
	e.expectIn(e.dataDir, "", code, stdout, stderr, args...)
}

// expectIn runs the command and checks exit code, exact stdout when
// wantOut is non-empty, and that stderr contains wantErr.
func (e *e2e) expectIn(dataDir, stdin string, code int, wantOut, wantErr string, args ...string) {
	e.t.Helper()
	got, out, errOut := e.runIn(dataDir, stdin, args...)
	if got != code || (wantOut != "" && out != wantOut) || !strings.Contains(errOut, wantErr) {
		e.t.Fatalf("%v: exit %d, stdout %q, stderr %q; want exit %d, stdout %q, stderr containing %q",
			args, got, out, errOut, code, wantOut, wantErr)
	}
}

func TestEndToEnd(t *testing.T) {
	bin, daemonBin := buildBinaries(t)
	dataDir := t.TempDir()
	socket := filepath.Join(t.TempDir(), "keycell.sock")
	daemon := startDaemonProcess(t, daemonBin, socket, dataDir)
	e := &e2e{t: t, bin: bin, socket: socket, dataDir: dataDir}

	e.expect(0, "", unencryptedWarning, "init", "--no-passphrase")
	e.expect(1, "", "keycell: "+identity.ErrExists.Error(), "init", "--no-passphrase")
	e.expect(0, "unlocked, no auto-lock\n", "", "unlock")
	e.expectIn(dataDir, "s3cret\n", 0, "", "", "store", "api/token", "-k", "api-token", "-a", "host=example.com")
	e.expect(0, "s3cret", "", "get", "api/token")
	e.expect(0, "example.com\n", "", "get", "--attr", "host", "api/token")
	e.expect(0, "api/token\n", "", "list")
	e.expect(0, "api/token\n", "", "list", "-k", "api-token", "-a", "host=example.com")
	e.expect(0, "", "", "delete", "api/token")
	if _, out, _ := e.run("", "list"); out != "" {
		t.Fatalf("list after delete: %q", out)
	}
	e.expect(0, "", "", "lock")
	e.expect(1, "", "keycell: daemon is locked, run 'keycell unlock'", "get", "api/token")

	e.expect(1, "", "keycell: no TTY for passphrase prompt", "passphrase")
	e.expect(1, "", "keycell: identity is not passphrase-protected", "passphrase", "--remove")

	encrypted := t.TempDir()
	if err := identity.Init(encrypted, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	e.expectIn(encrypted, "", 1, "", "keycell: no TTY for passphrase prompt", "unlock")

	e.expect(0, "socket:   "+socket+"\nidentity: UNENCRYPTED\ndaemon:   locked\n", "", "status")
	e.expectIn(encrypted, "", 0, "socket:   "+socket+"\nidentity: passphrase-protected\ndaemon:   locked\n", "", "status")

	if err := daemon.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := daemon.Wait(); err != nil {
		t.Fatalf("keycelld exit: %v", err)
	}
	e.expect(1, "socket:   "+socket+"\nidentity: UNENCRYPTED\ndaemon:   not running, run 'systemctl --user start keycell'\n", "", "status")
	e.expect(1, "", "keycell: daemon is not running, run 'systemctl --user start keycell'", "list")
}
