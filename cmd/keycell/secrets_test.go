package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// secrets is a store/get/delete/list runner with stdin content.
func (d *testDaemon) secrets(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	code, stderr := execIO(t, d.socket, d.dataDir, strings.NewReader(stdin), &stdout, d.prompt(), args...)
	return code, stdout.String(), stderr
}

func (d *testDaemon) mustStore(t *testing.T, name, value string, flags ...string) {
	t.Helper()
	code, _, errOut := d.secrets(t, value, append([]string{"store", name}, flags...)...)
	if code != 0 {
		t.Fatalf("store %s: exit %d, stderr %q", name, code, errOut)
	}
}

// openPTY returns the master and slave of a fresh pseudo terminal so a
// test can hand the CLI a stdin or stdout that is a terminal.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	rc, err := master.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) {
		if ioctlErr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); ioctlErr == nil {
			n, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCGPTN)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if ioctlErr != nil {
		t.Fatal(ioctlErr)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slave.Close() })
	return master, slave
}

func TestStoreGet(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)

	d.mustStore(t, "plain", "hunter2\n")
	code, out, _ := d.secrets(t, "", "get", "plain")
	if code != 0 || out != "hunter2" {
		t.Errorf("get: exit %d, stdout %q", code, out)
	}

	d.mustStore(t, "raw", "no newline")
	if _, out, _ := d.secrets(t, "", "get", "raw"); out != "no newline" {
		t.Errorf("get raw: %q", out)
	}
	d.mustStore(t, "multi", "a\n\n")
	if _, out, _ := d.secrets(t, "", "get", "multi"); out != "a\n" {
		t.Errorf("only one newline is trimmed: %q", out)
	}

	d.mustStore(t, "api/prod", "tok", "-k", "api-token", "-a", "host=example.com", "-a", "note=a,b=c")
	_, out, _ = d.secrets(t, "", "get", "--attr", "host", "api/prod")
	if out != "example.com\n" {
		t.Errorf("get --attr: %q", out)
	}
	_, out, _ = d.secrets(t, "", "get", "-a", "note", "api/prod")
	if out != "a,b=c\n" {
		t.Errorf("attribute value with comma and '=': %q", out)
	}
	code, _, errOut := d.secrets(t, "", "get", "--attr", "nope", "api/prod")
	if code != 1 || !strings.Contains(errOut, `attribute "nope" not set`) {
		t.Errorf("missing attr: exit %d, stderr %q", code, errOut)
	}

	_, out, _ = d.secrets(t, "", "get", "--json", "api/prod")
	var got secretJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got.Name != "api/prod" || got.Kind != "api-token" || got.Attributes["host"] != "example.com" || got.Created.IsZero() || got.Updated.IsZero() {
		t.Errorf("json: %+v", got)
	}
	if strings.Contains(out, "value") {
		t.Errorf("json leaks value:\n%s", out)
	}
	_, out, _ = d.secrets(t, "", "get", "--json", "plain")
	if !strings.Contains(out, `"attributes": {}`) || !strings.Contains(out, `"kind": "generic"`) {
		t.Errorf("json without attributes: %s", out)
	}

	d.mustStore(t, "api/prod", "tok2")
	_, out, _ = d.secrets(t, "", "get", "--json", "api/prod")
	if !strings.Contains(out, `"attributes": {}`) || !strings.Contains(out, `"kind": "generic"`) {
		t.Errorf("store replaces attributes and kind: %s", out)
	}
}

func TestStoreErrors(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	d.mustStore(t, "taken", "x")

	tests := []struct {
		name  string
		stdin string
		args  []string
		code  int
		err   string
	}{
		{"empty", "\n", []string{"store", "e"}, 1, "store: empty value"},
		{"no name", "x", []string{"store"}, 2, "takes exactly one name"},
		{"two names", "x", []string{"store", "a", "b"}, 2, "takes exactly one name"},
		{"attr without =", "x", []string{"store", "a", "-a", "host"}, 2, "expected key=value"},
		{"attr twice", "x", []string{"store", "a", "-a", "h=1", "-a", "h=2"}, 2, "key given twice"},
		{"bad kind", "x", []string{"store", "a", "-k", "Bad Kind"}, 1, "kind"},
		{"no-overwrite taken", "x", []string{"store", "taken", "--no-overwrite"}, 1, "store: taken already exists"},
		{"no-overwrite free", "x", []string{"store", "free", "--no-overwrite"}, 0, ""},
		{"get unknown", "", []string{"get", "nope"}, 1, "keycell: secret not found"},
		{"get attr and json", "", []string{"get", "-a", "x", "--json", "taken"}, 2, "mutually exclusive"},
		{"delete no names", "", []string{"delete"}, 2, "at least one name"},
		{"list positional", "", []string{"list", "x"}, 2, "takes no arguments"},
		{"list long and json", "", []string{"list", "-l", "--json"}, 2, "mutually exclusive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := d.secrets(t, tt.stdin, tt.args...)
			if code != tt.code || !strings.Contains(errOut, tt.err) {
				t.Errorf("exit %d, stderr %q; want %d, %q", code, errOut, tt.code, tt.err)
			}
		})
	}
	if _, out, _ := d.secrets(t, "", "get", "taken"); out != "x" {
		t.Errorf("taken was overwritten: %q", out)
	}
}

func TestStoreInteractive(t *testing.T) {
	d := startDaemon(t)
	_, slave := openPTY(t)

	t.Run("locked", func(t *testing.T) {
		d.answers = []string{"never"}
		var stdout bytes.Buffer
		code, errOut := execIO(t, d.socket, d.dataDir, slave, &stdout, d.prompt(), "store", "x")
		if code != 1 || !strings.Contains(errOut, "daemon is locked") || len(d.answers) != 1 {
			t.Fatalf("exit %d, stderr %q, answers left %d", code, errOut, len(d.answers))
		}
	})

	d.unlock(t, 0)
	t.Run("prompt", func(t *testing.T) {
		var prompts []string
		prompt := func(p string) ([]byte, error) {
			prompts = append(prompts, p)
			return []byte("typed"), nil
		}
		var stdout bytes.Buffer
		code, errOut := execIO(t, d.socket, d.dataDir, slave, &stdout, prompt, "store", "x")
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if len(prompts) != 1 || prompts[0] != "Value for x: " {
			t.Errorf("prompts %q", prompts)
		}
		if _, out, _ := d.secrets(t, "", "get", "x"); out != "typed" {
			t.Errorf("get: %q", out)
		}
	})
}

func TestGetAtTerminal(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	d.mustStore(t, "x", "abc")
	master, slave := openPTY(t)

	read := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := master.Read(buf)
		read <- string(buf[:n])
	}()
	code, errOut := execIO(t, d.socket, d.dataDir, strings.NewReader(""), slave, d.prompt(), "get", "x")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	select {
	case out := <-read:
		if strings.TrimRight(out, "\r\n") != "abc" || !strings.HasSuffix(out, "\n") {
			t.Errorf("terminal output %q", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing arrived at the terminal")
	}
}

func TestDelete(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	d.mustStore(t, "a", "1")
	d.mustStore(t, "b", "2")

	code, out, errOut := d.secrets(t, "", "delete", "a", "missing", "b")
	if code != 1 || out != "" || errOut != "keycell: delete: not found: missing\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := d.secrets(t, "", "list"); out != "" {
		t.Errorf("remaining: %q", out)
	}

	d.mustStore(t, "c", "3")
	if code, _, errOut := d.secrets(t, "", "delete", "c"); code != 0 || errOut != "" {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestList(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)

	if code, out, _ := d.secrets(t, "", "list"); code != 0 || out != "" {
		t.Errorf("empty list: exit %d, stdout %q", code, out)
	}
	if _, out, _ := d.secrets(t, "", "list", "-l"); out != "" {
		t.Errorf("empty list -l: %q", out)
	}
	if _, out, _ := d.secrets(t, "", "list", "--json"); out != "[]\n" {
		t.Errorf("empty list --json: %q", out)
	}

	d.mustStore(t, "git/github.com", "t1", "-k", "git-credential", "-a", "host=github.com", "-a", "username=alex")
	d.mustStore(t, "git/gitlab.com", "t2", "-k", "git-credential", "-a", "host=gitlab.com")
	d.mustStore(t, "docker/hub", "t3", "-k", "docker-registry")
	d.mustStore(t, "aaa", "t4")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"all", nil, "aaa\ndocker/hub\ngit/github.com\ngit/gitlab.com\n"},
		{"prefix", []string{"-p", "git/"}, "git/github.com\ngit/gitlab.com\n"},
		{"kind", []string{"--kind", "docker-registry"}, "docker/hub\n"},
		{"attr", []string{"-a", "host=github.com"}, "git/github.com\n"},
		{"attr and kind", []string{"-k", "git-credential", "-a", "username=alex"}, "git/github.com\n"},
		{"no match", []string{"-p", "zzz"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := d.secrets(t, "", append([]string{"list"}, tt.args...)...)
			if code != 0 || out != tt.want {
				t.Errorf("exit %d, stdout %q, stderr %q; want %q", code, out, errOut, tt.want)
			}
		})
	}

	_, out, _ := d.secrets(t, "", "list", "-l", "-p", "git/")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "ATTRIBUTES") {
		t.Fatalf("table:\n%s", out)
	}
	if !strings.Contains(lines[1], "git-credential") || !strings.HasSuffix(lines[1], "host=github.com,username=alex") {
		t.Errorf("row: %q", lines[1])
	}
	if !strings.Contains(lines[1], time.Now().Format("2006-01-02")) {
		t.Errorf("updated column: %q", lines[1])
	}

	_, out, _ = d.secrets(t, "", "list", "--json", "-k", "git-credential")
	var got []secretJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got) != 2 || got[0].Attributes["host"] != "github.com" {
		t.Errorf("json: %v\n%s", err, out)
	}
}

func TestSecretsDaemonState(t *testing.T) {
	d := startDaemon(t)
	cmds := [][]string{{"store", "x"}, {"get", "x"}, {"delete", "x"}, {"list"}, {"store", "x", "--no-overwrite"}}
	for _, args := range cmds {
		code, out, errOut := d.secrets(t, "v", args...)
		if code != 1 || out != "" || !strings.Contains(errOut, "daemon is locked, run 'keycell unlock'") {
			t.Errorf("%v locked: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
		code, _, errOut = d.secrets(t, "v", append([]string{"--socket", "/nonexistent/keycell.sock"}, args...)...)
		if code != 1 || !strings.Contains(errOut, "daemon is not running") {
			t.Errorf("%v not running: exit %d, stderr %q", args, code, errOut)
		}
	}
}
