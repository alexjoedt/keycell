package identity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	scryptWorkFactor = 10
	os.Exit(m.Run())
}

func TestGenerateParse(t *testing.T) {
	enc, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte("AGE-SECRET-KEY-1")) {
		t.Fatalf("unexpected encoding %q", enc)
	}
	id, err := Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != string(enc) {
		t.Fatal("parse changed the key")
	}
	if _, err := Parse([]byte("AGE-SECRET-KEY-1nope")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestLoad(t *testing.T) {
	enc, _ := Generate()
	pass := []byte("correct horse")

	tests := []struct {
		name  string
		setup func(dir string)
		pass  []byte
		form  Form
		err   error
	}{
		{"none", func(string) {}, pass, FormNone, ErrNotFound},
		{"plain", func(d string) { must(t, WritePlain(filepath.Join(d, PlainFile), enc)) }, nil, FormPlain, nil},
		{"plain ignores passphrase", func(d string) { must(t, WritePlain(filepath.Join(d, PlainFile), enc)) }, []byte("x"), FormPlain, nil},
		{"encrypted", func(d string) { must(t, WriteEncrypted(filepath.Join(d, EncryptedFile), enc, pass)) }, bytes.Clone(pass), FormEncrypted, nil},
		{"wrong passphrase", func(d string) { must(t, WriteEncrypted(filepath.Join(d, EncryptedFile), enc, pass)) }, []byte("wrong"), FormEncrypted, ErrWrongPassphrase},
		{"empty passphrase", func(d string) { must(t, WriteEncrypted(filepath.Join(d, EncryptedFile), enc, pass)) }, nil, FormEncrypted, ErrWrongPassphrase},
		{"both", func(d string) {
			must(t, WritePlain(filepath.Join(d, PlainFile), enc))
			must(t, WriteEncrypted(filepath.Join(d, EncryptedFile), enc, pass))
		}, bytes.Clone(pass), FormNone, ErrAmbiguous},
		{"plain garbage", func(d string) { must(t, os.WriteFile(filepath.Join(d, PlainFile), []byte("junk\n"), 0o600)) }, nil, FormPlain, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(dir)
			form, derr := Detect(dir)
			if form != tt.form {
				t.Fatalf("Detect: got %s, want %s", form, tt.form)
			}
			if errors.Is(tt.err, ErrAmbiguous) && !errors.Is(derr, ErrAmbiguous) {
				t.Fatalf("Detect: got %v, want ErrAmbiguous", derr)
			}
			got, err := Load(dir, tt.pass)
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Fatalf("got %v, want %v", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, enc) {
				t.Fatalf("loaded %q, want %q", got, enc)
			}
			if tt.form == FormEncrypted && !bytes.Equal(tt.pass, make([]byte, len(tt.pass))) {
				t.Fatal("passphrase not wiped")
			}
		})
	}
}

func TestWritePermissions(t *testing.T) {
	dir := t.TempDir()
	enc, _ := Generate()
	p := filepath.Join(dir, PlainFile)
	must(t, WritePlain(p, enc))
	must(t, WritePlain(p, enc))
	for _, name := range []string{p, p + ".bak"} {
		st, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s has mode %o", name, st.Mode().Perm())
		}
	}
	if err := WriteEncrypted(filepath.Join(dir, EncryptedFile), enc, nil); err == nil {
		t.Fatal("empty passphrase accepted")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
