package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/alexjoedt/keycell/pkg/keycell"
)

func TestReadServerURL(t *testing.T) {
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "https://index.docker.io/v1/", want: "https://index.docker.io/v1/"},
		{in: "ghcr.io\n", want: "ghcr.io"},
		{in: "  127.0.0.1:5000 \r\n", want: "127.0.0.1:5000"},
		{in: "", wantErr: "server URL missing"},
		{in: " \n", wantErr: "server URL missing"},
		{in: "a b", wantErr: "whitespace"},
		{in: "a\nb\n", wantErr: "whitespace"},
	}
	for _, tc := range tests {
		got, err := readServerURL(strings.NewReader(tc.in))
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: err = %v, want %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got (%q, %v), want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := readServerURL(strings.NewReader("")); !errors.Is(err, errNoServerURL) {
		t.Fatalf("err = %v, want errNoServerURL", err)
	}
}

func TestReadStoreRequest(t *testing.T) {
	tests := []struct {
		name, in string
		server   string
		user     string
		secret   string
		wantErr  string
	}{
		{name: "plain", in: `{"ServerURL":"ghcr.io","Username":"alex","Secret":"hunter2"}`, server: "ghcr.io", user: "alex", secret: "hunter2"},
		{name: "escapes", in: `{"ServerURL":"ghcr.io","Username":"alex","Secret":"a\"b\\c\/d\n\u00e4\ud83d\ude00"}` + "\n", server: "ghcr.io", user: "alex", secret: "a\"b\\c/d\nä😀"},
		{name: "empty secret", in: `{"ServerURL":"ghcr.io","Username":"alex","Secret":""}`, server: "ghcr.io", user: "alex", secret: ""},
		{name: "no server", in: `{"Username":"alex","Secret":"x"}`, wantErr: "server URL missing"},
		{name: "no username", in: `{"ServerURL":"ghcr.io","Secret":"x"}`, wantErr: "username missing"},
		{name: "no secret", in: `{"ServerURL":"ghcr.io","Username":"alex"}`, wantErr: "secret missing"},
		{name: "not json", in: `ghcr.io`, wantErr: "store request"},
		{name: "empty", in: ``, wantErr: "store request"},
		{name: "unknown field", in: `{"ServerURL":"ghcr.io","Username":"alex","Secret":"x","Token":"y"}`, wantErr: "unknown field"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, buf, err := readStoreRequest(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(buf) != tc.in {
				t.Fatalf("buf = %q, want the raw input", buf)
			}
			secret, err := unquote(req.Secret)
			if err != nil {
				t.Fatal(err)
			}
			if req.ServerURL != tc.server || req.Username != tc.user || string(secret) != tc.secret {
				t.Fatalf("got (%q, %q, %q), want (%q, %q, %q)", req.ServerURL, req.Username, secret, tc.server, tc.user, tc.secret)
			}
		})
	}
}

func TestUnquoteErrors(t *testing.T) {
	for _, in := range []string{`x`, `"`, `"\"`, `"\x"`, `"\u12"`, `"\u12G4"`, `"\ud83d"`, `"\ud83dA"`, `"\udc00"`} {
		if out, err := unquote([]byte(in)); err == nil {
			t.Errorf("%s: got %q, want error", in, out)
		}
	}
	if out, err := unquote([]byte(`"A"`)); err != nil || string(out) != "A" {
		t.Fatalf("got (%q, %v)", out, err)
	}
}

func TestSecretName(t *testing.T) {
	tests := map[string]string{
		"https://index.docker.io/v1/": "docker/index.docker.io",
		"ghcr.io":                     "docker/ghcr.io",
		"127.0.0.1:5000":              "docker/127.0.0.1:5000",
		"https://registry.example.com:8443/path/": "docker/registry.example.com:8443",
		"http://": "docker/http://",
	}
	for in, want := range tests {
		if got := secretName(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestMatch(t *testing.T) {
	d := startDaemon(t)
	c := d.client(t)
	ctx := context.Background()

	if s, err := match(ctx, c, "ghcr.io"); s != nil || !errors.Is(err, errNoMatch) {
		t.Fatalf("empty vault: got (%v, %v), want errNoMatch", s, err)
	}

	d.store(t, "docker/ghcr.io", "ghcr.io", "alex", "t1")
	d.store(t, "docker/index.docker.io", "https://index.docker.io/v1/", "alex", "t2")
	d.store(t, "other", "https://index.docker.io/v1/", "bob", "t3")

	s, err := match(ctx, c, "ghcr.io")
	if err != nil || s == nil || s.Name != "docker/ghcr.io" || s.Attributes["username"] != "alex" {
		t.Fatalf("one hit: got (%+v, %v)", s, err)
	}
	if s, err := match(ctx, c, "https://ghcr.io/"); s != nil || !errors.Is(err, errNoMatch) {
		t.Fatalf("literal compare: got (%v, %v), want errNoMatch", s, err)
	}
	_, err = match(ctx, c, "https://index.docker.io/v1/")
	var amb *ambiguousError
	if !errors.As(err, &amb) || err.Error() != "ambiguous match: docker/index.docker.io, other" {
		t.Fatalf("two hits: err = %v", err)
	}

	d.lock(t)
	if _, err := match(ctx, c, "ghcr.io"); !errors.Is(err, keycell.ErrLocked) {
		t.Fatalf("locked: err = %v, want ErrLocked", err)
	}
}
