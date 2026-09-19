package identity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexjoedt/keycell/internal/vault"
)

func TestInit(t *testing.T) {
	t.Run("encrypted", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "data")
		pass := []byte("correct horse")
		must(t, Init(dir, bytes.Clone(pass)))
		st, err := os.Stat(dir)
		must(t, err)
		if st.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %o", st.Mode().Perm())
		}
		if form, _ := Detect(dir); form != FormEncrypted {
			t.Fatalf("form %s", form)
		}
		assertVault(t, dir, bytes.Clone(pass))
	})
	t.Run("plain", func(t *testing.T) {
		dir := t.TempDir()
		must(t, Init(dir, nil))
		if form, _ := Detect(dir); form != FormPlain {
			t.Fatalf("form %s", form)
		}
		assertVault(t, dir, nil)
	})
	t.Run("wipes passphrase", func(t *testing.T) {
		pass := []byte("correct horse")
		must(t, Init(t.TempDir(), pass))
		if !bytes.Equal(pass, make([]byte, len(pass))) {
			t.Fatal("passphrase not wiped")
		}
	})
	t.Run("empty passphrase refused", func(t *testing.T) {
		if err := Init(t.TempDir(), []byte{}); err == nil {
			t.Fatal("empty passphrase accepted")
		}
	})

	occupied := []struct {
		name  string
		setup func(dir string)
	}{
		{"identity.age", func(d string) { must(t, Init(d, []byte("x"))) }},
		{"identity.txt", func(d string) { must(t, Init(d, nil)) }},
		{"vault only", func(d string) { must(t, os.WriteFile(filepath.Join(d, vault.File), []byte("x"), 0o600)) }},
		{"both identities", func(d string) {
			must(t, os.WriteFile(filepath.Join(d, PlainFile), []byte("x"), 0o600))
			must(t, os.WriteFile(filepath.Join(d, EncryptedFile), []byte("x"), 0o600))
		}},
	}
	for _, tt := range occupied {
		t.Run("occupied "+tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(dir)
			before := snapshot(t, dir)
			if err := Init(dir, []byte("y")); !errors.Is(err, ErrExists) {
				t.Fatalf("got %v, want ErrExists", err)
			}
			if after := snapshot(t, dir); !equalSnapshot(before, after) {
				t.Fatal("occupied directory was modified")
			}
		})
	}
}

func TestChangePassphrase(t *testing.T) {
	dir := t.TempDir()
	must(t, Init(dir, []byte("old")))
	before := snapshot(t, dir)

	if err := ChangePassphrase(dir, []byte("wrong"), []byte("new")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v, want ErrWrongPassphrase", err)
	}
	if !equalSnapshot(before, snapshot(t, dir)) {
		t.Fatal("wrong passphrase modified files")
	}

	must(t, ChangePassphrase(dir, []byte("old"), []byte("new")))
	if _, err := Load(dir, []byte("old")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase still works: %v", err)
	}
	assertVault(t, dir, []byte("new"))
	if !exists(filepath.Join(dir, EncryptedFile+".bak")) {
		t.Fatal("no .bak generation")
	}

	plain := t.TempDir()
	must(t, Init(plain, nil))
	if err := ChangePassphrase(plain, nil, []byte("new")); !errors.Is(err, ErrWrongForm) {
		t.Fatalf("plain form: got %v, want ErrWrongForm", err)
	}
}

func TestSetRemovePassphrase(t *testing.T) {
	dir := t.TempDir()
	must(t, Init(dir, nil))

	if err := RemovePassphrase(dir, nil); !errors.Is(err, ErrWrongForm) {
		t.Fatalf("remove on plain: got %v, want ErrWrongForm", err)
	}
	must(t, SetPassphrase(dir, []byte("pass")))
	if form, _ := Detect(dir); form != FormEncrypted {
		t.Fatalf("form %s after set", form)
	}
	assertVault(t, dir, []byte("pass"))

	if err := SetPassphrase(dir, []byte("again")); !errors.Is(err, ErrWrongForm) {
		t.Fatalf("set on encrypted: got %v, want ErrWrongForm", err)
	}
	if err := RemovePassphrase(dir, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v, want ErrWrongPassphrase", err)
	}
	if form, _ := Detect(dir); form != FormEncrypted {
		t.Fatalf("form %s after failed remove", form)
	}
	must(t, RemovePassphrase(dir, []byte("pass")))
	if form, _ := Detect(dir); form != FormPlain {
		t.Fatalf("form %s after remove", form)
	}
	assertVault(t, dir, nil)
}

func TestFormChangeAbort(t *testing.T) {
	dir := t.TempDir()
	must(t, Init(dir, nil))
	injected := errors.New("injected")
	removeFile = func(string) error { return injected }
	t.Cleanup(func() { removeFile = os.Remove })

	if err := SetPassphrase(dir, []byte("pass")); !errors.Is(err, injected) {
		t.Fatalf("got %v, want injected error", err)
	}
	for _, name := range []string{PlainFile, EncryptedFile} {
		if !exists(filepath.Join(dir, name)) {
			t.Fatalf("%s missing after abort", name)
		}
	}
	if _, err := Load(dir, []byte("pass")); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("got %v, want ErrAmbiguous", err)
	}
}

// assertVault proves the identity in dir opens the vault written there.
func assertVault(t *testing.T, dir string, pass []byte) {
	t.Helper()
	encoded, err := Load(dir, pass)
	must(t, err)
	id, err := Parse(encoded)
	must(t, err)
	v, err := vault.Read(filepath.Join(dir, vault.File), id)
	must(t, err)
	if v.Version != vault.Version || len(v.Secrets) != 0 {
		t.Fatalf("unexpected vault: %+v", v)
	}
}

func snapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	must(t, err)
	out := map[string][]byte{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		must(t, err)
		out[e.Name()] = b
	}
	return out
}

func equalSnapshot(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			return false
		}
	}
	return true
}
