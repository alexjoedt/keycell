package main

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseEnvMapping(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		noFile  bool
		flags   []string
		want    []envEntry
		wantErr string
	}{
		{name: "empty", noFile: true},
		{name: "file only, sorted",
			file: "B=two\nA=one\n",
			want: []envEntry{{"A", "one"}, {"B", "two"}}},
		{name: "comments, blank lines, whitespace",
			file: "  # comment\n\n  A = svc/a  \n\t\n#B=x\n",
			want: []envEntry{{"A", "svc/a"}}},
		{name: "flag overrides file",
			file:  "A=file\nB=file\n",
			flags: []string{"A=flag"},
			want:  []envEntry{{"A", "flag"}, {"B", "file"}}},
		{name: "later entry wins",
			file:  "A=1\nA=2\n",
			flags: []string{"B=1", "B=2"},
			want:  []envEntry{{"A", "2"}, {"B", "2"}}},
		{name: "name keeps its own equals sign",
			file: "A=k=v\n",
			want: []envEntry{{"A", "k=v"}}},
		{name: "file line without equals",
			file: "A=one\nBROKEN\n", wantErr: "keycell: exec: keycell.env:2: expected VAR=name"},
		{name: "file empty variable",
			file: "=one\n", wantErr: "keycell: exec: keycell.env:1: empty variable name"},
		{name: "file empty name",
			file: "A=\n", wantErr: "keycell: exec: keycell.env:1: empty secret name"},
		{name: "file invalid variable",
			file: "1A=one\n", wantErr: `keycell: exec: keycell.env:1: invalid variable name "1A"`},
		{name: "file variable with dash",
			file: "A-B=one\n", wantErr: `keycell: exec: keycell.env:1: invalid variable name "A-B"`},
		{name: "flag without equals",
			noFile: true, flags: []string{"A"}, wantErr: `keycell: exec: -e "A": expected VAR=name`},
		{name: "flag empty name",
			noFile: true, flags: []string{"A= "}, wantErr: `keycell: exec: -e "A= ": empty secret name`},
		{name: "flag invalid variable",
			noFile: true, flags: []string{"a.b=x"}, wantErr: `keycell: exec: -e "a.b=x": invalid variable name "a.b"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var file io.Reader
			if !tt.noFile {
				file = strings.NewReader(tt.file)
			}
			got, err := parseEnvMapping(file, envFileName, tt.flags)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// execNoDaemon runs exec in dir without a daemon: only the parsing and
// usage paths are exercised.
func execNoDaemon(t *testing.T, dir string, args ...string) (int, string) {
	t.Helper()
	t.Chdir(dir)
	code, _, errOut := execCLI(t, filepath.Join(dir, "none.sock"), dir, (&setupPrompt{}).read, append([]string{"exec"}, args...)...)
	return code, errOut
}

func TestExecUsageErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no command", []string{"-e", "A=x"}, "keycell: exec: missing command"},
		{"empty after separator", []string{"--"}, "keycell: exec: missing command"},
		{"invalid flag entry", []string{"-e", "A", "--", "true"}, `keycell: exec: -e "A": expected VAR=name`},
		{"missing env file", []string{"--env-file", filepath.Join(dir, "nope"), "--", "true"},
			"keycell: exec: open " + filepath.Join(dir, "nope") + ": no such file or directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, errOut := execNoDaemon(t, dir, tt.args...)
			if code != 2 || !strings.HasPrefix(errOut, tt.wantErr+"\n") {
				t.Errorf("exit %d, stderr %q, want exit 2 with %q", code, errOut, tt.wantErr)
			}
		})
	}
}

func TestExecEnvFile(t *testing.T) {
	t.Run("keycell.env is optional", func(t *testing.T) {
		code, errOut := execNoDaemon(t, t.TempDir(), "--", "true")
		if code == 2 || strings.Contains(errOut, envFileName) {
			t.Errorf("exit %d, stderr %q: missing keycell.env must not be a usage error", code, errOut)
		}
	})
	t.Run("invalid line in keycell.env", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, envFileName), "A=one\n\nnope\n")
		code, errOut := execNoDaemon(t, dir, "--", "true")
		want := "keycell: exec: keycell.env:3: expected VAR=name\n"
		if code != 2 || errOut != want {
			t.Errorf("exit %d, stderr %q, want exit 2 with %q", code, errOut, want)
		}
	})
	t.Run("explicit --env-file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "other.env")
		writeFile(t, path, "=x\n")
		code, errOut := execNoDaemon(t, dir, "--env-file", path, "--", "true")
		want := "keycell: exec: " + path + ":1: empty variable name\n"
		if code != 2 || errOut != want {
			t.Errorf("exit %d, stderr %q, want exit 2 with %q", code, errOut, want)
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// execDaemon runs exec against d from an empty working directory.
func (d *testDaemon) execDaemon(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Chdir(t.TempDir())
	return d.exec(t, append([]string{"exec"}, args...)...)
}

func TestExecResolve(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	d.mustStore(t, "svc/a", "alpha")
	d.mustStore(t, "svc/b", "beta")

	t.Run("dry-run lists the mapping in order", func(t *testing.T) {
		code, out, errOut := d.execDaemon(t, "--dry-run", "-e", "B=svc/b", "-e", "A=svc/a", "--", "true")
		if code != 0 || errOut != "" || out != "A <- svc/a\nB <- svc/b\n" {
			t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})
	t.Run("dry-run with an empty mapping", func(t *testing.T) {
		code, out, errOut := d.execDaemon(t, "--dry-run", "--", "true")
		if code != 0 || out != "" || errOut != "" {
			t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})
	t.Run("missing names are collected", func(t *testing.T) {
		code, out, errOut := d.execDaemon(t, "--dry-run", "-e", "A=svc/a", "-e", "X=svc/x", "-e", "Y=svc/y", "--", "true")
		want := "keycell: exec: not found: svc/x\nkeycell: exec: not found: svc/y\n"
		if code != 1 || errOut != want {
			t.Errorf("exit %d, stderr %q, want exit 1 with %q", code, errOut, want)
		}
		if out != "A <- svc/a\nX <- svc/x\nY <- svc/y\n" {
			t.Errorf("stdout %q", out)
		}
	})
	t.Run("invalid name is reported per entry", func(t *testing.T) {
		long := strings.Repeat("n", 257)
		code, _, errOut := d.execDaemon(t, "--dry-run", "-e", "A=svc/a", "-e", "B="+long, "--", "true")
		if code != 1 || !strings.HasPrefix(errOut, "keycell: exec: "+long+": ") || strings.Count(errOut, "\n") != 1 {
			t.Errorf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("values never reach stdout or stderr", func(t *testing.T) {
		_, out, errOut := d.execDaemon(t, "--dry-run", "-e", "A=svc/a", "-e", "X=svc/x", "--", "true")
		if strings.Contains(out+errOut, "alpha") {
			t.Errorf("value leaked: stdout %q, stderr %q", out, errOut)
		}
	})
	t.Run("locked", func(t *testing.T) {
		code, _, errOut := d.exec(t, "lock")
		if code != 0 {
			t.Fatalf("lock: exit %d, stderr %q", code, errOut)
		}
		code, out, errOut := d.execDaemon(t, "--dry-run", "-e", "A=svc/a", "--", "true")
		if code != 1 || errOut != "keycell: daemon is locked, run 'keycell unlock'\n" || out != "A <- svc/a\n" {
			t.Errorf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})
}

func TestExecNotRunning(t *testing.T) {
	code, errOut := execNoDaemon(t, t.TempDir(), "-e", "A=svc/a", "--", "true")
	if code != 1 || errOut != "keycell: daemon is not running, run 'systemctl --user start keycell'\n" {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}
