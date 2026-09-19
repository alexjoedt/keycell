package daemon

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/vault"
)

type testDaemon struct {
	sock    string
	enc     []byte
	session *Session
	server  *Server
	done    chan error
	cancel  context.CancelFunc
}

func startDaemon(t *testing.T, opts ...func(*Server)) *testDaemon {
	t.Helper()
	st, s, enc := newTestStore(t)
	sock := filepath.Join(t.TempDir(), "keycell.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(s, st, slog.New(slog.DiscardHandler))
	for _, opt := range opts {
		opt(srv)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &testDaemon{sock: sock, enc: enc, session: s, server: srv, done: make(chan error, 1), cancel: cancel}
	go func() { d.done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-d.done
	})
	return d
}

type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func (d *testDaemon) dial(t *testing.T) *client {
	t.Helper()
	conn, err := net.Dial("unix", d.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &client{t: t, conn: conn, r: bufio.NewReader(conn)}
}

// call sends one raw line and returns the parsed response.
func (c *client) call(line string) map[string]any {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, line+"\n"); err != nil {
		c.t.Fatal(err)
	}
	resp, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read response to %s: %v", line, err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(resp), &m); err != nil {
		c.t.Fatalf("bad response %q: %v", resp, err)
	}
	return m
}

func code(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		return e["code"].(string)
	}
	return "ok"
}

func TestServeAllMethods(t *testing.T) {
	d := startDaemon(t)
	c := d.dial(t)
	b64 := base64.StdEncoding.EncodeToString

	m := c.call(`{"id":1,"method":"status"}`)
	if res := m["result"].(map[string]any); code(m) != "ok" || res["locked"] != true || res["protocol"] != float64(1) || m["id"] != float64(1) {
		t.Fatalf("status: %v", m)
	}
	for _, line := range []string{
		`{"id":2,"method":"get","params":{"name":"x"}}`,
		`{"id":2,"method":"list"}`,
		`{"id":2,"method":"store","params":{"name":"x","kind":"k","value":"dg=="}}`,
		`{"id":2,"method":"delete","params":{"name":"x"}}`,
	} {
		if m := c.call(line); code(m) != "LOCKED" {
			t.Fatalf("%s: got %v, want LOCKED", line, m)
		}
	}

	if m := c.call(`{"id":3,"method":"unlock","params":{"identity":"` + b64([]byte("AGE-SECRET-KEY-1NOPE")) + `"}}`); code(m) != "INVALID_ARGUMENT" {
		t.Fatalf("malformed identity: %v", m)
	}
	other, _ := identity.Generate()
	if m := c.call(`{"id":3,"method":"unlock","params":{"identity":"` + b64(other) + `"}}`); code(m) != "INVALID_ARGUMENT" {
		t.Fatalf("wrong identity: %v", m)
	}
	if locked, _ := d.session.Status(); !locked {
		t.Fatal("wrong identity left the session unlocked")
	}
	m = c.call(`{"id":"u","method":"unlock","params":{"identity":"` + b64(d.enc) + `","for":3600}}`)
	if code(m) != "ok" || m["id"] != "u" {
		t.Fatalf("unlock: %v", m)
	}
	m = c.call(`{"id":4,"method":"status"}`)
	if res := m["result"].(map[string]any); res["locked"] != false || res["locks_at"] == nil {
		t.Fatalf("status after unlock: %v", m)
	}

	if m := c.call(`{"id":5,"method":"store","params":{"name":"git/github.com","kind":"git-credential","attributes":{"host":"github.com"},"value":"` + b64([]byte("ghp_1")) + `"}}`); code(m) != "ok" {
		t.Fatalf("store: %v", m)
	}
	if m := c.call(`{"id":5,"method":"store","params":{"name":"","kind":"k","value":"dg=="}}`); code(m) != "INVALID_ARGUMENT" || !strings.Contains(m["error"].(map[string]any)["message"].(string), "name is empty") {
		t.Fatalf("store invalid: %v", m)
	}
	if m := c.call(`{"id":5,"method":"store","params":{"name":"x","kind":"k","value":"dg==","extra":1}}`); code(m) != "INVALID_ARGUMENT" {
		t.Fatalf("store unknown field: %v", m)
	}
	m = c.call(`{"id":6,"method":"get","params":{"name":"git/github.com"}}`)
	if res := m["result"].(map[string]any); code(m) != "ok" || res["value"] != b64([]byte("ghp_1")) || res["kind"] != "git-credential" {
		t.Fatalf("get: %v", m)
	}
	if m := c.call(`{"id":6,"method":"get","params":{"name":"nope"}}`); code(m) != "NOT_FOUND" {
		t.Fatalf("get missing: %v", m)
	}
	m = c.call(`{"id":7,"method":"list","params":{"kind":"git-credential"}}`)
	if res := m["result"].([]any); code(m) != "ok" || len(res) != 1 || res[0].(map[string]any)["value"] != nil {
		t.Fatalf("list: %v", m)
	}
	if m := c.call(`{"id":7,"method":"list","params":{"prefix":"docker/"}}`); code(m) != "ok" || len(m["result"].([]any)) != 0 {
		t.Fatalf("list empty: %v", m)
	}
	if m := c.call(`{"id":8,"method":"delete","params":{"name":"git/github.com"}}`); code(m) != "ok" {
		t.Fatalf("delete: %v", m)
	}
	if m := c.call(`{"id":8,"method":"delete","params":{"name":"git/github.com"}}`); code(m) != "NOT_FOUND" {
		t.Fatalf("delete again: %v", m)
	}

	if m := c.call(`{"id":9,"method":"lock"}`); code(m) != "ok" {
		t.Fatalf("lock: %v", m)
	}
	if m := c.call(`{"id":10,"method":"get","params":{"name":"x"}}`); code(m) != "LOCKED" {
		t.Fatalf("after lock: %v", m)
	}
}

func TestServeProtocolErrors(t *testing.T) {
	d := startDaemon(t)
	c := d.dial(t)
	if m := c.call(`{"id":1,"method":`); code(m) != "PROTOCOL" || m["id"] != nil {
		t.Fatalf("broken json: %v", m)
	}
	if m := c.call(`{"method":"status"}`); code(m) != "PROTOCOL" || m["id"] != nil {
		t.Fatalf("missing id: %v", m)
	}
	if m := c.call(`{"id":"k","method":"exists"}`); code(m) != "PROTOCOL" || m["id"] != "k" {
		t.Fatalf("unknown method: %v", m)
	}
	if m := c.call(`{"id":2,"method":"status"}`); code(m) != "ok" {
		t.Fatalf("connection unusable after protocol error: %v", m)
	}
	// The server may close the connection before the whole line is
	// written, so the write error is irrelevant.
	_, _ = io.WriteString(c.conn, "{"+strings.Repeat(" ", 2*1024*1024))
	line, err := c.r.ReadString('\n')
	if err != nil || !strings.Contains(line, `"PROTOCOL"`) {
		t.Fatalf("too long: %q %v", line, err)
	}
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Fatal("connection stayed open after oversized line")
	}
}

func TestRejectForeignUID(t *testing.T) {
	d := startDaemon(t, func(s *Server) {
		s.peerUID = func(*net.UnixConn) (uint32, error) { return s.uid + 1, nil }
	})
	c := d.dial(t)
	_, _ = io.WriteString(c.conn, `{"id":1,"method":"status"}`+"\n")
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Fatal("rejected connection answered")
	}
}

func TestListenSingleInstance(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "keycell.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(sock); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, %v", info.Mode(), err)
	}
	if info, err := os.Stat(filepath.Dir(sock)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v, %v", info.Mode(), err)
	}
	if _, err := Listen(sock); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("got %v, want ErrAlreadyRunning", err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Fatal("test setup: stale socket missing")
	}
	ln2, err := Listen(sock)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln2.Close()
}

func TestShutdown(t *testing.T) {
	d := startDaemon(t)
	c := d.dial(t)
	if m := c.call(`{"id":1,"method":"unlock","params":{"identity":"` + base64.StdEncoding.EncodeToString(d.enc) + `"}}`); code(m) != "ok" {
		t.Fatalf("unlock: %v", m)
	}
	d.cancel()
	select {
	case err := <-d.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	if locked, _ := d.session.Status(); !locked {
		t.Fatal("session not locked on shutdown")
	}
	if _, err := os.Stat(d.sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket not removed on shutdown")
	}
	if _, err := c.r.ReadString('\n'); err != io.EOF {
		t.Fatalf("open connection not closed: %v", err)
	}
	d.done <- nil
}

func TestUnlockWithoutVault(t *testing.T) {
	d := startDaemon(t, func(s *Server) { s.store.path = filepath.Join(t.TempDir(), vault.File) })
	c := d.dial(t)
	m := c.call(`{"id":1,"method":"unlock","params":{"identity":"` + base64.StdEncoding.EncodeToString(d.enc) + `"}}`)
	if code(m) != "INTERNAL" || !strings.Contains(m["error"].(map[string]any)["message"].(string), "keycell init") {
		t.Fatalf("unlock without vault: %v", m)
	}
	if locked, _ := d.session.Status(); !locked {
		t.Fatal("session unlocked although the vault is missing")
	}
}
