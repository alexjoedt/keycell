package main

import (
	"bufio"
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
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keycelld")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// listenNotify plays systemd: a datagram socket that collects every
// sd_notify state the daemon sends.
func listenNotify(t *testing.T) (path string, states <-chan string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ch := make(chan string, 8)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			ch <- string(buf[:n])
		}
	}()
	return path, ch
}

func waitFor(t *testing.T, states <-chan string, want string) {
	t.Helper()
	select {
	case got := <-states:
		if got != want {
			t.Fatalf("sd_notify: got %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("sd_notify: no %q within 5s", want)
	}
}

func TestBinaryShutdownOnSIGTERM(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "keycell.sock")
	notifyPath, states := listenNotify(t)

	var stderr bytes.Buffer
	cmd := exec.Command(bin, "--socket", sock, "--data-dir", filepath.Join(dir, "data"), "--log-level", "debug")
	cmd.Env = append(os.Environ(), "NOTIFY_SOCKET="+notifyPath)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, states, "READY=1")

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial after READY: %v\n%s", err, stderr.String())
	}
	if _, err := conn.Write([]byte(`{"id":1,"method":"status"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, `"locked":true`) {
		t.Fatalf("status: %q %v", line, err)
	}
	conn.Close()

	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if cmd.ProcessState != nil {
		t.Fatal("daemon exited on SIGHUP")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("exit: %v\n%s", err, stderr.String())
	}
	waitFor(t, states, "STOPPING=1")
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket still present after shutdown: %v", err)
	}
	for _, want := range []string{"starting keycelld", "keycell init", "data_dir", "stopped"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr lacks %q:\n%s", want, stderr.String())
		}
	}
}

func TestBinaryRejectsBadConfig(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--socket", filepath.Join(t.TempDir(), "s"), "--auto-lock", "soon")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), "--auto-lock") {
		t.Fatalf("got %v, %q", err, out)
	}
}
