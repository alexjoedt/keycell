package main

import (
	"strings"
	"testing"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/tty"
)

// unlockCLI runs unlock against d with a recording prompter.
func unlockCLI(t *testing.T, d *testDaemon, answers []string, args ...string) (int, string, string, *setupPrompt) {
	t.Helper()
	p := &setupPrompt{answers: answers}
	code, out, errOut := execCLI(t, d.socket, d.dataDir, p.read, append([]string{"unlock"}, args...)...)
	return code, out, errOut, p
}

// encrypt swaps the daemon's plain identity for identity.age with pw.
func encrypt(t *testing.T, d *testDaemon, pw string) {
	t.Helper()
	if err := identity.SetPassphrase(d.dataDir, []byte(pw)); err != nil {
		t.Fatal(err)
	}
}

func TestUnlockPlain(t *testing.T) {
	d := startDaemon(t)
	code, out, errOut, p := unlockCLI(t, d, nil)
	if code != 0 || errOut != "" {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if len(p.prompts) != 0 {
		t.Errorf("prompted %q", p.prompts)
	}
	if !strings.Contains(out, "unlocked, no auto-lock") {
		t.Errorf("stdout %q", out)
	}
	if d.locked(t) {
		t.Fatal("daemon still locked")
	}

	code, out, _, p = unlockCLI(t, d, nil)
	if code != 0 || !strings.Contains(out, "already unlocked, no auto-lock") || len(p.prompts) != 0 {
		t.Errorf("second unlock: exit %d, stdout %q, prompts %q", code, out, p.prompts)
	}
}

func TestUnlockEncrypted(t *testing.T) {
	d := startDaemon(t)
	encrypt(t, d, "pw")

	t.Run("wrong three times", func(t *testing.T) {
		code, _, errOut, p := unlockCLI(t, d, []string{"a", "b", "c"})
		if code != 1 || !strings.Contains(errOut, "keycell: wrong passphrase") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if len(p.prompts) != 3 || p.prompts[0] != "Passphrase: " {
			t.Errorf("prompts %q", p.prompts)
		}
		if !d.locked(t) {
			t.Fatal("daemon unlocked")
		}
		p.assertZeroed(t)
	})

	t.Run("no tty", func(t *testing.T) {
		code, _, errOut, _ := unlockCLI(t, d, nil)
		if code != 1 || !strings.Contains(errOut, tty.ErrNoTTY.Error()) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})

	t.Run("second attempt with --for", func(t *testing.T) {
		code, out, errOut, p := unlockCLI(t, d, []string{"x", "pw"}, "--for", "90m")
		if code != 0 || errOut != "keycell: wrong passphrase, try again\n" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		if !strings.Contains(out, "unlocked, locks in 1h30m") {
			t.Errorf("stdout %q", out)
		}
		if d.locked(t) {
			t.Fatal("daemon still locked")
		}
		p.assertZeroed(t)
	})

	t.Run("already unlocked keeps timer", func(t *testing.T) {
		code, out, _, p := unlockCLI(t, d, []string{"pw"}, "--for", "0")
		if code != 0 || !strings.Contains(out, "already unlocked, locks in 1h30m") || len(p.prompts) != 0 {
			t.Errorf("exit %d, stdout %q, prompts %q", code, out, p.prompts)
		}
	})
}

func TestUnlockFor(t *testing.T) {
	d := startDaemon(t)
	tests := []struct {
		name string
		dur  string
		code int
		out  string
	}{
		{"zero", "0", 0, "unlocked, no auto-lock"},
		{"invalid", "soon", 2, ""},
		{"negative", "-1h", 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d.exec(t, "lock")
			code, out, errOut, _ := unlockCLI(t, d, nil, "--for", tt.dur)
			if code != tt.code {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
			if tt.code == 0 && !strings.Contains(out, tt.out) {
				t.Errorf("stdout %q", out)
			}
			if tt.code != 0 && !strings.Contains(errOut, "invalid duration") {
				t.Errorf("stderr %q", errOut)
			}
		})
	}

	d.exec(t, "lock")
	unlockCLI(t, d, nil, "--for", "2h")
	code, out, _ := d.exec(t, "status")
	if code != 0 || !strings.Contains(out, "locks in 2h0m") {
		t.Errorf("status after --for 2h: %q", out)
	}
}

func TestUnlockErrors(t *testing.T) {
	d := startDaemon(t)
	t.Run("not running", func(t *testing.T) {
		code, _, errOut, p := unlockCLI(t, d, []string{"pw"}, "--socket", "/nonexistent/keycell.sock")
		if code != 1 || !strings.Contains(errOut, "daemon is not running") || len(p.prompts) != 0 {
			t.Fatalf("exit %d, stderr %q, prompts %q", code, errOut, p.prompts)
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		if err := identity.WriteEncrypted(d.dataDir+"/"+identity.EncryptedFile, []byte("AGE-SECRET-KEY-1"), []byte("x")); err != nil {
			t.Fatal(err)
		}
		code, _, errOut, _ := unlockCLI(t, d, nil)
		if code != 1 || !strings.Contains(errOut, identity.ErrAmbiguous.Error()) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
	t.Run("no identity", func(t *testing.T) {
		code, _, errOut := execCLI(t, d.socket, t.TempDir(), (&setupPrompt{}).read, "unlock")
		if code != 1 || !strings.Contains(errOut, "run 'keycell init'") {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
	})
}
