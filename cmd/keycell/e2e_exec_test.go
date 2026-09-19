package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// execRun runs keycell exec from dir with extra variables in the
// environment and returns exit code, stdout and stderr. Unlike runIn it
// keeps the test as parent, so $PPID of the started command is checkable.
func (e *e2e) execRun(dir, stdin string, extra []string, args ...string) (int, string, string) {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(e.bin, append([]string{"exec"}, args...)...)
	cmd.Dir = dir
	cmd.Env = e2eEnv(e.socket, e.dataDir, extra...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		e.t.Fatalf("%v: %v", args, err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

func TestEndToEndExec(t *testing.T) {
	bin, daemonBin := buildBinaries(t)
	dataDir := t.TempDir()
	socket := filepath.Join(t.TempDir(), "keycell.sock")
	startDaemonProcess(t, daemonBin, socket, dataDir)
	e := &e2e{t: t, bin: bin, socket: socket, dataDir: dataDir}
	e.expect(0, "", unencryptedWarning, "init", "--no-passphrase")
	e.expect(0, "unlocked, no auto-lock\n", "", "unlock")
	e.expectIn(dataDir, "alpha", 0, "", "", "store", "svc/a")
	e.expectIn(dataDir, "beta", 0, "", "", "store", "svc/b")

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, envFileName), "# project secrets\nB=svc/b\n")

	t.Run("env from flag and keycell.env, secrets replace variables", func(t *testing.T) {
		code, out, errOut := e.execRun(dir, "", []string{"A=old", "B=old", "KEEP=1"}, "-e", "A=svc/a", "--", "env")
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		count := map[string]int{}
		for _, l := range lines {
			k, _, _ := strings.Cut(l, "=")
			count[k]++
		}
		for _, want := range []string{"A=alpha", "B=beta", "KEEP=1", "KEYCELL_SOCKET=" + socket} {
			if !slices.Contains(lines, want) {
				t.Errorf("env missing %q:\n%s", want, out)
			}
		}
		if count["A"] != 1 || count["B"] != 1 {
			t.Errorf("A appears %d times, B %d times, want once each:\n%s", count["A"], count["B"], out)
		}
	})
	t.Run("no parent process between test and command", func(t *testing.T) {
		code, out, errOut := e.execRun(dir, "", nil, "--", "sh", "-c", "echo $PPID")
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if ppid, err := strconv.Atoi(strings.TrimSpace(out)); err != nil || ppid != os.Getpid() {
			t.Errorf("$PPID = %q, want %d", out, os.Getpid())
		}
	})
	t.Run("exit code is the command's", func(t *testing.T) {
		if code, _, errOut := e.execRun(dir, "", nil, "-e", "A=svc/a", "--", "sh", "-c", "exit 3"); code != 3 || errOut != "" {
			t.Errorf("exit %d, stderr %q, want 3", code, errOut)
		}
	})
	t.Run("stdin reaches the command", func(t *testing.T) {
		if code, out, _ := e.execRun(dir, "ping", nil, "--", "cat"); code != 0 || out != "ping" {
			t.Errorf("exit %d, stdout %q", code, out)
		}
	})
	t.Run("missing name aborts before the start", func(t *testing.T) {
		marker := filepath.Join(dir, "marker")
		code, out, errOut := e.execRun(dir, "", nil, "-e", "X=svc/x", "--", "touch", marker)
		if code != 1 || out != "" || errOut != "keycell: exec: not found: svc/x\n" {
			t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Error("command ran despite the missing name")
		}
	})
	t.Run("command not found", func(t *testing.T) {
		code, _, errOut := e.execRun(dir, "", nil, "--", "keycell-no-such-command")
		if code != 1 || errOut != "keycell: exec: keycell-no-such-command: executable file not found in $PATH\n" {
			t.Errorf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("command not executable", func(t *testing.T) {
		plain := filepath.Join(dir, "plain")
		writeFile(t, plain, "")
		code, _, errOut := e.execRun(dir, "", nil, "--", plain)
		if code != 1 || errOut != "keycell: exec: "+plain+": permission denied\n" {
			t.Errorf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("locked daemon", func(t *testing.T) {
		e.expect(0, "", "", "lock")
		code, _, errOut := e.execRun(dir, "", nil, "-e", "A=svc/a", "--", "true")
		if code != 1 || errOut != "keycell: daemon is locked, run 'keycell unlock'\n" {
			t.Errorf("exit %d, stderr %q", code, errOut)
		}
	})
}
