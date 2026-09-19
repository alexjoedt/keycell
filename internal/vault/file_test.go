package vault

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func testVault(t *testing.T) *Vault {
	t.Helper()
	ts := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	v := New()
	v.Secrets["github/token"] = &Secret{Kind: "git-credential", Value: []byte("ghp_secret"), Created: ts, Updated: ts}
	return v
}

func testIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestReadWrite(t *testing.T) {
	id := testIdentity(t)
	path := filepath.Join(t.TempDir(), File)

	if err := Write(path, id, testVault(t)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm %o, want 0600", perm)
	}
	if _, err := os.Stat(path + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first write must not create a backup, got %v", err)
	}

	got, err := Read(path, id)
	if err != nil {
		t.Fatal(err)
	}
	if s := got.Secrets["github/token"]; s == nil || string(s.Value) != "ghp_secret" {
		t.Fatalf("round trip lost data: %+v", s)
	}

	if _, err := Read(path, testIdentity(t)); !errors.Is(err, ErrWrongIdentity) {
		t.Fatalf("wrong identity: got %v, want ErrWrongIdentity", err)
	}
	if _, err := Read(filepath.Join(t.TempDir(), File), id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: got %v, want ErrNotExist", err)
	}
}

func TestWriteBackup(t *testing.T) {
	id := testIdentity(t)
	path := filepath.Join(t.TempDir(), File)

	first := testVault(t)
	if err := Write(path, id, first); err != nil {
		t.Fatal(err)
	}
	second := testVault(t)
	second.Secrets["github/token"].Value = []byte("rotated")
	if err := Write(path, id, second); err != nil {
		t.Fatal(err)
	}

	cur, err := Read(path, id)
	if err != nil {
		t.Fatal(err)
	}
	bak, err := Read(path+".bak", id)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur.Secrets["github/token"].Value) != "rotated" || string(bak.Secrets["github/token"].Value) != "ghp_secret" {
		t.Fatalf("backup generation wrong: cur=%q bak=%q", cur.Secrets["github/token"].Value, bak.Secrets["github/token"].Value)
	}
}

// TestWriteAbort injects a failure between the finished temp file and the
// rename: a directory occupies vault.age.bak, so the backup rename fails.
func TestWriteAbort(t *testing.T) {
	id := testIdentity(t)
	dir := t.TempDir()
	path := filepath.Join(dir, File)

	if err := Write(path, id, testVault(t)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".bak", 0o700); err != nil {
		t.Fatal(err)
	}

	second := testVault(t)
	second.Secrets["github/token"].Value = []byte("rotated")
	if err := Write(path, id, second); err == nil {
		t.Fatal("write succeeded, want injected failure")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("vault.age changed after aborted write")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// TestEmergencyPath decrypts a written file with age alone, as the age CLI
// would, and finds the schema from 01-01.
func TestEmergencyPath(t *testing.T) {
	id := testIdentity(t)
	path := filepath.Join(t.TempDir(), File)
	if err := Write(path, id, testVault(t)); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"secrets":{"github/token":{"kind":"git-credential","value":"Z2hwX3NlY3JldA==","created":"2026-09-20T12:00:00Z","updated":"2026-09-20T12:00:00Z"}}}`
	if string(plain) != want {
		t.Fatalf("plaintext drift:\n got %s\nwant %s", plain, want)
	}
}
