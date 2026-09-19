package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/vault"
)

// canonical re-encodes a vault document with sorted keys so two exports
// compare independent of field order.
func canonical(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("invalid JSON %q: %v", b, err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestExportMatchesVaultFile(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	d.mustStore(t, "plain", "hunter2")
	d.mustStore(t, "api/prod", "tok\nmulti", "-k", "api-token", "-a", "host=example.com")

	code, out, errOut := d.secrets(t, "", "export")
	if code != 0 {
		t.Fatalf("export: exit %d, stderr %q", code, errOut)
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Errorf("export ends with a newline: %q", out)
	}

	id, err := identity.Parse(d.identity)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Read(filepath.Join(d.dataDir, vault.File), id)
	if err != nil {
		t.Fatal(err)
	}
	file, err := vault.Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := canonical(t, []byte(out)), canonical(t, file); got != want {
		t.Errorf("export differs from vault file:\n got %s\nwant %s", got, want)
	}

	if _, out, _ := d.secrets(t, "", "export", "extra"); out != "" {
		t.Errorf("export with argument printed %q", out)
	}
}

func TestExportEmptyVault(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	code, out, _ := d.secrets(t, "", "export")
	if code != 0 || out != `{"version":1,"secrets":{}}`+"\n" {
		t.Errorf("empty export: exit %d, %q", code, out)
	}
}

func TestImportRoundtrip(t *testing.T) {
	src := startDaemon(t)
	src.unlock(t, 0)
	src.mustStore(t, "plain", "hunter2")
	src.mustStore(t, "api/prod", "tok", "-k", "api-token", "-a", "host=example.com", "-a", "note=a,b=c")
	_, doc, _ := src.secrets(t, "", "export")
	_, wantList, _ := src.secrets(t, "", "list", "--json")

	dst := startDaemon(t)
	dst.unlock(t, 0)
	code, out, errOut := dst.secrets(t, doc, "import")
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("import from stdin: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	_, gotList, _ := dst.secrets(t, "", "list", "--json")
	type entry struct {
		Name       string            `json:"name"`
		Kind       string            `json:"kind"`
		Attributes map[string]string `json:"attributes"`
	}
	var want, got []entry
	if err := json.Unmarshal([]byte(wantList), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(gotList), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("list after import: got %d secrets, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Kind != want[i].Kind || len(got[i].Attributes) != len(want[i].Attributes) {
			t.Errorf("secret %d: got %+v, want %+v", i, got[i], want[i])
		}
		for k, v := range want[i].Attributes {
			if got[i].Attributes[k] != v {
				t.Errorf("%s: attribute %s = %q, want %q", want[i].Name, k, got[i].Attributes[k], v)
			}
		}
	}
	if _, out, _ := dst.secrets(t, "", "get", "api/prod"); out != "tok" {
		t.Errorf("value after import: %q", out)
	}

	file := filepath.Join(t.TempDir(), "vault.json")
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	third := startDaemon(t)
	third.unlock(t, 0)
	if code, _, errOut := third.secrets(t, "", "import", file); code != 0 {
		t.Errorf("import from file: exit %d, stderr %q", code, errOut)
	}
	if _, out, _ := third.secrets(t, "", "list"); out != "api/prod\nplain\n" {
		t.Errorf("list after file import: %q", out)
	}
}

func TestImportNoOverwrite(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	d.mustStore(t, "keep", "old")
	doc := `{"version":1,"secrets":{
		"keep":{"kind":"generic","value":"bmV3","created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"},
		"fresh":{"kind":"generic","value":"bmV3","created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}}}`

	code, _, errOut := d.secrets(t, doc, "import", "--no-overwrite")
	if code != 0 || errOut != "keycell: import: skipped, already exists: keep\n" {
		t.Errorf("--no-overwrite: exit %d, stderr %q", code, errOut)
	}
	if _, out, _ := d.secrets(t, "", "get", "keep"); out != "old" {
		t.Errorf("kept secret was replaced: %q", out)
	}
	if _, out, _ := d.secrets(t, "", "get", "fresh"); out != "new" {
		t.Errorf("new secret missing: %q", out)
	}

	if code, _, _ := d.secrets(t, doc, "import"); code != 0 {
		t.Errorf("import without flag: exit %d", code)
	}
	if _, out, _ := d.secrets(t, "", "get", "keep"); out != "new" {
		t.Errorf("upsert did not replace: %q", out)
	}
}

func TestImportErrors(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	rec := func(kind string) string {
		return `{"kind":"` + kind + `","value":"eA==","created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}`
	}
	tests := []struct {
		name   string
		stdin  string
		args   []string
		code   int
		stderr string
	}{
		{"newer version", `{"version":2,"secrets":{}}`, nil, 1, "unsupported schema version"},
		{"not json", `nope`, nil, 1, "keycell: import: invalid document:"},
		{"unknown field", `{"version":1,"secrets":{},"extra":1}`, nil, 1, "invalid document"},
		{"two files", ``, []string{"a", "b"}, 2, "at most one file"},
		{"missing file", ``, []string{filepath.Join(t.TempDir(), "none.json")}, 1, "keycell: import: open"},
		{"invalid kind", `{"version":1,"secrets":{"aaa":` + rec("generic") + `,"bbb":` + rec("Bad Kind") + `}}`, nil, 1, "keycell: import: bbb: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := d.secrets(t, tt.stdin, append([]string{"import"}, tt.args...)...)
			if code != tt.code || !strings.Contains(errOut, tt.stderr) {
				t.Errorf("exit %d, stderr %q; want exit %d containing %q", code, errOut, tt.code, tt.stderr)
			}
		})
	}
	if _, out, _ := d.secrets(t, "", "list"); out != "aaa\n" {
		t.Errorf("secrets stored before the failure stay: %q", out)
	}

	if code, _, _ := d.exec(t, "lock"); code != 0 {
		t.Fatal("lock failed")
	}
	code, _, errOut := d.secrets(t, `{"version":1,"secrets":{"x":`+rec("generic")+`}}`, "import")
	if code != 1 || !strings.Contains(errOut, "daemon is locked") {
		t.Errorf("import while locked: exit %d, stderr %q", code, errOut)
	}
	code, _, errOut = d.secrets(t, "", "export")
	if code != 1 || !strings.Contains(errOut, "daemon is locked") {
		t.Errorf("export while locked: exit %d, stderr %q", code, errOut)
	}
}
