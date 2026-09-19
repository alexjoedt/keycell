package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/tty"
)

// setupPrompt answers in order and keeps every slice it handed out so
// the test can check they were zeroed.
type setupPrompt struct {
	answers []string
	prompts []string
	handed  [][]byte
}

func (p *setupPrompt) read(prompt string) ([]byte, error) {
	p.prompts = append(p.prompts, prompt)
	if len(p.answers) == 0 {
		return nil, tty.ErrNoTTY
	}
	b := []byte(p.answers[0])
	p.answers = p.answers[1:]
	p.handed = append(p.handed, b)
	return b, nil
}

func (p *setupPrompt) assertZeroed(t *testing.T) {
	t.Helper()
	for i, b := range p.handed {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("answer %d not zeroed: %q", i, b)
		}
	}
}

// setup runs init or passphrase against dataDir with the given answers.
func setup(t *testing.T, dataDir string, answers []string, args ...string) (int, string, string, *setupPrompt) {
	t.Helper()
	p := &setupPrompt{answers: answers}
	socket := filepath.Join(dataDir, "none.sock")
	code, out, errOut := execCLI(t, socket, dataDir, p.read, args...)
	return code, out, errOut, p
}

func assertForm(t *testing.T, dir string, want identity.Form, pass string) {
	t.Helper()
	form, err := identity.Detect(dir)
	if err != nil || form != want {
		t.Fatalf("form %s, err %v; want %s", form, err, want)
	}
	if form == identity.FormNone {
		return
	}
	var p []byte
	if pass != "" {
		p = []byte(pass)
	}
	id, err := identity.Load(dir, p)
	if err != nil {
		t.Fatalf("load with %q: %v", pass, err)
	}
	clear(id)
}

func TestInit(t *testing.T) {
	t.Run("passphrase", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "keycell")
		code, out, errOut, p := setup(t, dir, []string{"pw", "pw"}, "init")
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		for _, want := range []string{"initialized " + dir, "systemctl --user enable --now keycell", "keycell unlock"} {
			if !strings.Contains(out, want) {
				t.Errorf("stdout missing %q:\n%s", want, out)
			}
		}
		if got := p.prompts; len(got) != 2 || got[0] != "New passphrase: " || got[1] != "Repeat passphrase: " {
			t.Errorf("prompts %q", got)
		}
		assertForm(t, dir, identity.FormEncrypted, "pw")
		p.assertZeroed(t)
	})

	t.Run("no-passphrase", func(t *testing.T) {
		dir := t.TempDir()
		code, _, errOut, p := setup(t, dir, nil, "init", "--no-passphrase")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if len(p.prompts) != 0 {
			t.Errorf("prompted %q", p.prompts)
		}
		if !strings.Contains(errOut, "identity is stored unencrypted; anyone with read access to identity.txt can decrypt the vault") {
			t.Errorf("stderr %q", errOut)
		}
		assertForm(t, dir, identity.FormPlain, "")
	})

	t.Run("mismatch", func(t *testing.T) {
		dir := t.TempDir()
		code, _, errOut, p := setup(t, dir, []string{"pw", "pq"}, "init")
		if code != 1 || !strings.Contains(errOut, "passphrases do not match") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		assertForm(t, dir, identity.FormNone, "")
		p.assertZeroed(t)
	})

	t.Run("exists", func(t *testing.T) {
		dir := t.TempDir()
		if err := identity.Init(dir, nil); err != nil {
			t.Fatal(err)
		}
		code, _, errOut, _ := setup(t, dir, nil, "init", "--no-passphrase")
		if code != 1 || !strings.Contains(errOut, identity.ErrExists.Error()) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
}

func TestPassphrase(t *testing.T) {
	encrypted := func(t *testing.T) string {
		dir := t.TempDir()
		if err := identity.Init(dir, []byte("pw")); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	plain := func(t *testing.T) string {
		dir := t.TempDir()
		if err := identity.Init(dir, nil); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("change", func(t *testing.T) {
		dir := encrypted(t)
		code, _, errOut, p := setup(t, dir, []string{"pw", "new", "new"}, "passphrase")
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if got := p.prompts; len(got) != 3 || got[0] != "Current passphrase: " || got[1] != "New passphrase: " {
			t.Errorf("prompts %q", got)
		}
		assertForm(t, dir, identity.FormEncrypted, "new")
		p.assertZeroed(t)
	})

	t.Run("wrong current three times", func(t *testing.T) {
		dir := encrypted(t)
		code, _, errOut, p := setup(t, dir, []string{"a", "new", "new", "b", "c"}, "passphrase")
		if code != 1 || !strings.Contains(errOut, "keycell: wrong passphrase") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if got := strings.Count(errOut, "wrong passphrase, try again"); got != 2 {
			t.Errorf("%d retry hints, want 2; stderr %q", got, errOut)
		}
		if len(p.prompts) != 5 || p.prompts[4] != "Current passphrase: " {
			t.Errorf("prompts %q", p.prompts)
		}
		assertForm(t, dir, identity.FormEncrypted, "pw")
		p.assertZeroed(t)
	})

	t.Run("set on plain", func(t *testing.T) {
		dir := plain(t)
		code, _, errOut, p := setup(t, dir, []string{"new", "new"}, "passphrase")
		if code != 0 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if got := p.prompts; len(got) != 2 || got[0] != "New passphrase: " {
			t.Errorf("prompts %q", got)
		}
		assertForm(t, dir, identity.FormEncrypted, "new")
		p.assertZeroed(t)
	})

	t.Run("remove", func(t *testing.T) {
		dir := encrypted(t)
		code, _, errOut, p := setup(t, dir, []string{"pw"}, "passphrase", "--remove")
		if code != 0 || !strings.Contains(errOut, unencryptedWarning) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if got := p.prompts; len(got) != 1 || got[0] != "Current passphrase: " {
			t.Errorf("prompts %q", got)
		}
		assertForm(t, dir, identity.FormPlain, "")
		p.assertZeroed(t)
	})

	t.Run("remove on plain", func(t *testing.T) {
		dir := plain(t)
		code, _, errOut, p := setup(t, dir, nil, "passphrase", "--remove")
		if code != 1 || !strings.Contains(errOut, "identity is not passphrase-protected") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if len(p.prompts) != 0 {
			t.Errorf("prompted %q", p.prompts)
		}
	})

	t.Run("no identity", func(t *testing.T) {
		code, _, errOut, _ := setup(t, t.TempDir(), nil, "passphrase")
		if code != 1 || !strings.Contains(errOut, "run 'keycell init'") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})

	t.Run("no tty", func(t *testing.T) {
		dir := encrypted(t)
		code, _, errOut, _ := setup(t, dir, nil, "passphrase")
		if code != 1 || !strings.Contains(errOut, tty.ErrNoTTY.Error()) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
}
