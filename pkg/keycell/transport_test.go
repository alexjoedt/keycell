package keycell

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexjoedt/keycell/internal/protocol"
)

func TestConnectSocketAndStatus(t *testing.T) {
	d := startDaemon(t)
	c := d.client(t)
	if c.Socket() != d.socket {
		t.Fatalf("Socket = %q, want %q", c.Socket(), d.socket)
	}

	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Locked || st.Protocol != protocol.Version || !st.LocksAt.IsZero() {
		t.Fatalf("Status = %+v", st)
	}
	if err := c.Lock(context.Background()); err != nil {
		t.Fatalf("Lock while locked: %v", err)
	}
}

func TestNotRunning(t *testing.T) {
	ctx := context.Background()
	missing := filepath.Join(t.TempDir(), "keycell.sock")
	_, err := ConnectSocket(ctx, missing)
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("missing socket: %v, want ErrNotRunning", err)
	}

	stale := filepath.Join(t.TempDir(), "keycell.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	_, err = ConnectSocket(ctx, stale)
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("stale socket: %v, want ErrNotRunning", err)
	}
}

// fakeDaemon answers every connection with reply and closes it.
func fakeDaemon(t *testing.T, reply func(req *protocol.Request) []byte) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "keycell.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				req, err := protocol.NewReader(conn).ReadRequest()
				if err != nil {
					return
				}
				if out := reply(req); out != nil {
					_, _ = conn.Write(out)
				}
			}()
		}
	}()
	return socket
}

func TestProtocolErrors(t *testing.T) {
	tests := []struct {
		name  string
		reply func(*protocol.Request) []byte
	}{
		{"closed without response", func(*protocol.Request) []byte { return nil }},
		{"garbage", func(*protocol.Request) []byte { return []byte("not json\n") }},
		{"wrong id", func(*protocol.Request) []byte { return []byte(`{"id":"other","result":{}}` + "\n") }},
		{"result type mismatch", func(r *protocol.Request) []byte {
			return []byte(`{"id":` + string(r.ID) + `,"result":{"locked":"yes"}}` + "\n")
		}},
		{"line too long", func(*protocol.Request) []byte {
			return append(bytes.Repeat([]byte("x"), protocol.MaxLineLen+1), '\n')
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{socket: fakeDaemon(t, tt.reply)}
			_, err := c.Status(context.Background())
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestDaemonErrorMapping(t *testing.T) {
	socket := fakeDaemon(t, func(r *protocol.Request) []byte {
		return []byte(`{"id":` + string(r.ID) + `,"error":{"code":"LOCKED","message":"daemon is locked"}}` + "\n")
	})
	c := &Client{socket: socket}
	err := c.Lock(context.Background())
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != "LOCKED" || e.Message != "daemon is locked" {
		t.Fatalf("errors.As = %v, %+v", err, e)
	}
	if want := "keycell: lock: LOCKED: daemon is locked"; err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestContextDeadline(t *testing.T) {
	socket := fakeDaemon(t, func(*protocol.Request) []byte {
		time.Sleep(2 * time.Second)
		return nil
	})
	c := &Client{socket: socket}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Status(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("call took %v, deadline not applied", time.Since(start))
	}
}

func TestBuffersWiped(t *testing.T) {
	const marker = "MARKER-7f3a"
	socket := fakeDaemon(t, func(r *protocol.Request) []byte {
		return []byte(`{"id":` + string(r.ID) + `,"result":{"value":"` + marker + `"}}` + "\n")
	})
	c := &Client{socket: socket}
	var res struct {
		Value string `json:"value"`
	}
	req, resp, err := c.roundTrip(context.Background(), protocol.MethodGet, struct {
		Name string `json:"name"`
	}{Name: marker}, &res)
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != marker {
		t.Fatalf("decoded %q, want %q", res.Value, marker)
	}
	for name, b := range map[string][]byte{"request params": req.Params, "response result": resp.Result} {
		if len(b) == 0 || !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("%s not zeroed: %q", name, b)
		}
	}
}
