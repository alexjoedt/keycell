package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alexjoedt/keycell/pkg/keycell"
)

// exec runs the helper in-process against the daemon's socket and
// returns exit code, stdout and stderr.
func (d *testDaemon) exec(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return execHelper(t, d.socket, stdin, args...)
}

const (
	locked     = "docker-credential-keycell: daemon is locked, run 'keycell unlock'\n"
	notRunning = "docker-credential-keycell: daemon is not running, run 'systemctl --user start keycell'\n"
)

func TestGet(t *testing.T) {
	d := startDaemon(t)
	d.store(t, "docker/ghcr.io", "ghcr.io", "alex", "ghp_x\"y\\z\n\x01ä")
	d.store(t, "docker/index.docker.io", "https://index.docker.io/v1/", "alex", "t2")
	d.store(t, "other", "https://index.docker.io/v1/", "bob", "t3")

	code, out, errOut := d.exec(t, "ghcr.io\n", "get")
	expect(t, code, out, errOut, 0, `{"ServerURL":"ghcr.io","Username":"alex","Secret":"ghp_x\"y\\z\n\u0001ä"}`+"\n", "")
	var resp struct {
		ServerURL string `json:"ServerURL"`
		Username  string `json:"Username"`
		Secret    string `json:"Secret"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil || resp.Secret != "ghp_x\"y\\z\n\x01ä" {
		t.Fatalf("decode: %v, %+v", err, resp)
	}

	code, out, errOut = d.exec(t, "https://ghcr.io/", "get")
	expect(t, code, out, errOut, 1, notFound+"\n", "")

	code, out, errOut = d.exec(t, "https://index.docker.io/v1/", "get")
	expect(t, code, out, errOut, 1, "", "docker-credential-keycell: ambiguous match: docker/index.docker.io, other\n")

	code, out, errOut = d.exec(t, "\n", "get")
	expect(t, code, out, errOut, 1, "", "docker-credential-keycell: server URL missing\n")

	d.lock(t)
	code, out, errOut = d.exec(t, "ghcr.io", "get")
	expect(t, code, out, errOut, 1, "", locked)

	code, out, errOut = execHelper(t, filepath.Join(t.TempDir(), "none.sock"), "ghcr.io", "get")
	expect(t, code, out, errOut, 1, "", notRunning)
}

func TestQuote(t *testing.T) {
	for _, in := range []string{"", "plain", `"\/`, "\n\r\t\x00\x1f\x7f", "ä😀", "<>&", "\xff\xfe"} {
		var got string
		if err := json.Unmarshal(quote([]byte(in)), &got); err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		std, _ := json.Marshal(in)
		var want string
		_ = json.Unmarshal(std, &want)
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestList(t *testing.T) {
	d := startDaemon(t)
	code, out, errOut := d.exec(t, "", "list")
	expect(t, code, out, errOut, 0, "{}\n", "")

	d.store(t, "docker/ghcr.io", "ghcr.io", "alex", "t1")
	d.store(t, "docker/index.docker.io", "https://index.docker.io/v1/", "bob", "t2")
	c := d.client(t)
	if err := c.Store(t.Context(), secret("no-server", map[string]string{"username": "x"}, "t3")); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(t.Context(), secret("git/ghcr.io", map[string]string{"host": "ghcr.io"}, "t4", "git-credential")); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = d.exec(t, "", "list")
	expect(t, code, out, errOut, 0, `{"ghcr.io":"alex","https://index.docker.io/v1/":"bob"}`+"\n", "")

	d.lock(t)
	code, out, errOut = d.exec(t, "", "list")
	expect(t, code, out, errOut, 0, "{}\n", locked)

	code, out, errOut = execHelper(t, filepath.Join(t.TempDir(), "none.sock"), "", "list")
	expect(t, code, out, errOut, 1, "", notRunning)
}

func login(server, user, secret string) string {
	b, _ := json.Marshal(map[string]string{"ServerURL": server, "Username": user, "Secret": secret})
	return string(b)
}

// get fetches a secret's attributes and value straight from the daemon.
func (d *testDaemon) get(t *testing.T, name string) (map[string]string, string) {
	t.Helper()
	s, err := d.client(t).Get(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Value.Destroy()
	return s.Attributes, string(s.Value.Expose())
}

func (d *testDaemon) names(t *testing.T) []string {
	t.Helper()
	secs, err := d.client(t).List(t.Context(), keycell.Filter{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(secs))
	for i, s := range secs {
		names[i] = s.Name
	}
	return names
}

func TestStore(t *testing.T) {
	d := startDaemon(t)

	code, out, errOut := d.exec(t, login("https://index.docker.io/v1/", "alex", "t1"), "store")
	expect(t, code, out, errOut, 0, "", "")
	attrs, value := d.get(t, "docker/index.docker.io")
	if attrs["server"] != "https://index.docker.io/v1/" || attrs["username"] != "alex" || value != "t1" {
		t.Fatalf("new: got %v %q", attrs, value)
	}

	code, out, errOut = d.exec(t, login("https://index.docker.io/v1/", "bob", "t2"), "store")
	expect(t, code, out, errOut, 0, "", "")
	attrs, value = d.get(t, "docker/index.docker.io")
	if attrs["username"] != "bob" || value != "t2" {
		t.Fatalf("overwrite: got %v %q", attrs, value)
	}
	if got := d.names(t); !reflect.DeepEqual(got, []string{"docker/index.docker.io"}) {
		t.Fatalf("names = %v", got)
	}

	c := d.client(t)
	if err := c.Store(t.Context(), secret("work", map[string]string{"server": "ghcr.io", "username": "alex", "team": "x"}, "t3")); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = d.exec(t, login("ghcr.io", "carol", "t4"), "store")
	expect(t, code, out, errOut, 0, "", "")
	attrs, value = d.get(t, "work")
	if !reflect.DeepEqual(attrs, map[string]string{"server": "ghcr.io", "username": "carol", "team": "x"}) || value != "t4" {
		t.Fatalf("overwrite by name: got %v %q", attrs, value)
	}

	d.store(t, "dup", "ghcr.io", "dan", "t5")
	code, out, errOut = d.exec(t, login("ghcr.io", "erin", "t6"), "store")
	expect(t, code, out, errOut, 1, "", "docker-credential-keycell: ambiguous match: dup, work\n")
	if _, value := d.get(t, "work"); value != "t4" {
		t.Fatalf("ambiguous wrote: %q", value)
	}

	code, out, errOut = d.exec(t, `{"ServerURL":"ghcr.io","Secret":"x"}`, "store")
	expect(t, code, out, errOut, 1, "", "docker-credential-keycell: username missing\n")
	code, out, errOut = d.exec(t, `nope`, "store")
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "docker-credential-keycell: store request: ") {
		t.Fatalf("got (%d, %q, %q)", code, out, errOut)
	}

	d.lock(t)
	code, out, errOut = d.exec(t, login("new.example.com", "alex", "t7"), "store")
	expect(t, code, out, errOut, 1, "", locked)
	d.unlock(t)
	if got := d.names(t); len(got) != 3 {
		t.Fatalf("locked store wrote: %v", got)
	}

	code, out, errOut = execHelper(t, filepath.Join(t.TempDir(), "none.sock"), login("ghcr.io", "alex", "t"), "store")
	expect(t, code, out, errOut, 1, "", notRunning)
}

func TestErase(t *testing.T) {
	d := startDaemon(t)
	d.store(t, "docker/ghcr.io", "ghcr.io", "alex", "t1")
	d.store(t, "a", "https://index.docker.io/v1/", "alex", "t2")
	d.store(t, "b", "https://index.docker.io/v1/", "bob", "t3")

	code, out, errOut := d.exec(t, "ghcr.io\n", "erase")
	expect(t, code, out, errOut, 0, "", "")
	code, out, errOut = d.exec(t, "ghcr.io", "erase")
	expect(t, code, out, errOut, 0, "", "")

	code, out, errOut = d.exec(t, "https://index.docker.io/v1/", "erase")
	expect(t, code, out, errOut, 1, "", "docker-credential-keycell: ambiguous match: a, b\n")
	if got := d.names(t); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("names = %v", got)
	}

	code, out, errOut = d.exec(t, "", "erase")
	expect(t, code, out, errOut, 1, "", "docker-credential-keycell: server URL missing\n")

	d.lock(t)
	code, out, errOut = d.exec(t, "ghcr.io", "erase")
	expect(t, code, out, errOut, 1, "", locked)
	code, out, errOut = execHelper(t, filepath.Join(t.TempDir(), "none.sock"), "ghcr.io", "erase")
	expect(t, code, out, errOut, 1, "", notRunning)
}

// TestLoginLogout runs the sequence docker produces: login stores,
// list shows it, get answers, logout erases, get misses.
func TestLoginLogout(t *testing.T) {
	d := startDaemon(t)
	const server = "127.0.0.1:5000"
	code, out, errOut := d.exec(t, login(server, "alex", "pw"), "store")
	expect(t, code, out, errOut, 0, "", "")
	code, out, errOut = d.exec(t, "", "list")
	expect(t, code, out, errOut, 0, `{"127.0.0.1:5000":"alex"}`+"\n", "")
	code, out, errOut = d.exec(t, server, "get")
	expect(t, code, out, errOut, 0, `{"ServerURL":"127.0.0.1:5000","Username":"alex","Secret":"pw"}`+"\n", "")
	code, out, errOut = d.exec(t, server, "erase")
	expect(t, code, out, errOut, 0, "", "")
	code, out, errOut = d.exec(t, "", "list")
	expect(t, code, out, errOut, 0, "{}\n", "")
	code, out, errOut = d.exec(t, server, "get")
	expect(t, code, out, errOut, 1, notFound+"\n", "")
}
