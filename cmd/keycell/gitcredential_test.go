package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/alexjoedt/keycell/pkg/keycell"
)

func TestParseGitRequest(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    gitRequest
		wantErr string
	}{
		{
			name: "all fields, stops at blank line",
			in:   "protocol=https\nhost=github.com\nusername=alex\npath=org/repo.git\n\nhost=ignored\n",
			want: gitRequest{protocol: "https", host: "github.com", username: "alex", path: "org/repo.git"},
		},
		{
			name: "skips other keys, keeps the password",
			in:   "protocol=https\nhost=github.com\npassword=hunter2\npassword_expiry_utc=1\noauth_refresh_token=x\nwwwauth[]=Basic realm=\"x\"\ncapability[]=authtype\nbogus=1\n",
			want: gitRequest{protocol: "https", host: "github.com", password: []byte("hunter2")},
		},
		{
			name: "value keeps further equals signs",
			in:   "host=h\npath=a=b\n",
			want: gitRequest{host: "h", path: "a=b"},
		},
		{
			name: "eof without trailing newline",
			in:   "host=h",
			want: gitRequest{host: "h"},
		},
		{name: "empty input", in: "", wantErr: "host missing"},
		{name: "no host", in: "protocol=https\n", wantErr: "host missing"},
		{name: "line without equals", in: "host=h\nnonsense\n", wantErr: "line 2: no '='"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGitRequest(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	if _, err := parseGitRequest(strings.NewReader("")); !errors.Is(err, errNoHost) {
		t.Fatalf("empty input err = %v, want errNoHost", err)
	}
}

func gitSecret(name string, attrs ...string) keycell.Secret {
	s := keycell.Secret{Name: name, Kind: gitKind, Attributes: map[string]string{}}
	for i := 0; i+1 < len(attrs); i += 2 {
		s.Attributes[attrs[i]] = attrs[i+1]
	}
	return s
}

func TestMatchGitCredential(t *testing.T) {
	host := gitSecret("git/github.com", "host", "github.com")
	alex := gitSecret("git/github.com/alex", "host", "github.com", "username", "alex")
	bob := gitSecret("git/github.com/bob", "host", "github.com", "username", "bob")
	httpsAlex := gitSecret("work", "host", "github.com", "username", "alex", "protocol", "https")
	pathOnly := gitSecret("repo", "host", "github.com", "path", "org/repo.git")
	other := gitSecret("git/gitlab.com", "host", "gitlab.com")
	wrongKind := keycell.Secret{Name: "generic", Kind: "generic", Attributes: map[string]string{"host": "github.com"}}

	tests := []struct {
		name      string
		cands     []keycell.Secret
		req       gitRequest
		want      string
		ambiguous []string
	}{
		{name: "no candidates", req: gitRequest{host: "github.com"}},
		{name: "other host only", cands: []keycell.Secret{other}, req: gitRequest{host: "github.com"}},
		{name: "wrong kind", cands: []keycell.Secret{wrongKind}, req: gitRequest{host: "github.com"}},
		{name: "one match, host only", cands: []keycell.Secret{host, other}, req: gitRequest{host: "github.com", username: "x"}, want: "git/github.com"},
		{name: "set attribute matches exactly", cands: []keycell.Secret{alex, bob}, req: gitRequest{host: "github.com", username: "bob"}, want: "git/github.com/bob"},
		{name: "request without username takes the one with it", cands: []keycell.Secret{host, alex}, req: gitRequest{host: "github.com"}, want: "git/github.com/alex"},
		{name: "two usernames for a request without one", cands: []keycell.Secret{alex, bob}, req: gitRequest{host: "github.com"}, ambiguous: []string{"git/github.com/alex", "git/github.com/bob"}},
		{name: "more specific wins", cands: []keycell.Secret{host, alex, httpsAlex}, req: gitRequest{host: "github.com", username: "alex", protocol: "https"}, want: "work"},
		{name: "specific loses when it mismatches", cands: []keycell.Secret{host, alex}, req: gitRequest{host: "github.com", username: "bob"}, want: "git/github.com"},
		{name: "path pins the match", cands: []keycell.Secret{host, pathOnly}, req: gitRequest{host: "github.com", path: "org/repo.git"}, want: "repo"},
		{name: "tie is ambiguous, names sorted", cands: []keycell.Secret{pathOnly, alex}, req: gitRequest{host: "github.com", username: "alex", path: "org/repo.git"}, ambiguous: []string{"git/github.com/alex", "repo"}},
		{name: "duplicate host-only entries", cands: []keycell.Secret{host, gitSecret("a", "host", "github.com")}, req: gitRequest{host: "github.com"}, ambiguous: []string{"a", "git/github.com"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := matchGitCredential(tc.cands, tc.req)
			if tc.ambiguous != nil {
				ae, ok := errors.AsType[*ambiguousError](err)
				if !ok {
					t.Fatalf("err = %v, want ambiguousError", err)
				}
				if strings.Join(ae.names, ",") != strings.Join(tc.ambiguous, ",") {
					t.Fatalf("names = %v, want %v", ae.names, tc.ambiguous)
				}
				return
			}
			if tc.want == "" {
				if !errors.Is(err, errNoMatch) {
					t.Fatalf("err = %v, want errNoMatch", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != tc.want {
				t.Fatalf("got %s, want %s", got.Name, tc.want)
			}
		})
	}
}

func TestGitCredentialGet(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)
	d.mustStore(t, "git/github.com", "tok-host", "-k", gitKind, "-a", "host=github.com")
	d.mustStore(t, "git/github.com/alex", "tok-alex", "-k", gitKind, "-a", "host=github.com", "-a", "username=alex")
	d.mustStore(t, "git/gitlab.com", "line1\nline2", "-k", gitKind, "-a", "host=gitlab.com")
	d.mustStore(t, "other", "x", "-a", "host=github.com")

	tests := []struct {
		name       string
		stdin      string
		wantCode   int
		wantOut    string
		wantStderr string
	}{
		{name: "username match", stdin: "protocol=https\nhost=github.com\nusername=alex\n\n", wantOut: "username=alex\npassword=tok-alex\n"},
		{name: "no username in the request, most specific wins", stdin: "protocol=https\nhost=github.com\n", wantOut: "username=alex\npassword=tok-alex\n"},
		{name: "host only secret serves any username", stdin: "protocol=https\nhost=github.com\nusername=carol\n", wantOut: "password=tok-host\n"},
		{name: "unknown host", stdin: "protocol=https\nhost=example.com\n"},
		{name: "no host", stdin: "protocol=https\n"},
		{name: "empty input"},
		{name: "bad line", stdin: "host=github.com\nnope\n", wantCode: 1, wantStderr: "keycell: git-credential: line 2: no '=' in \"nope\"\n"},
		{name: "value with newline", stdin: "host=gitlab.com\n", wantCode: 1, wantStderr: "keycell: git-credential: value of git/gitlab.com contains a newline\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := d.secrets(t, tc.stdin, "git-credential", "get")
			if code != tc.wantCode || out != tc.wantOut || errOut != tc.wantStderr {
				t.Fatalf("exit %d, stdout %q, stderr %q; want %d, %q, %q", code, out, errOut, tc.wantCode, tc.wantOut, tc.wantStderr)
			}
		})
	}

	t.Run("ambiguous", func(t *testing.T) {
		d.mustStore(t, "dup", "tok-dup", "-k", gitKind, "-a", "host=github.com", "-a", "username=bob")
		code, out, errOut := d.secrets(t, "host=github.com\n", "git-credential", "get")
		if code != 1 || out != "" || errOut != "keycell: git-credential: ambiguous match: dup, git/github.com/alex\n" {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})

	t.Run("usage", func(t *testing.T) {
		code, _, errOut := d.secrets(t, "", "git-credential", "bogus")
		if code != 2 || !strings.Contains(errOut, `unknown subcommand "bogus"`) {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		code, _, _ = d.secrets(t, "", "git-credential", "get", "extra")
		if code != 2 {
			t.Fatalf("get with argument: exit %d", code)
		}
	})

	t.Run("locked", func(t *testing.T) {
		if code, _, _ := d.exec(t, "lock"); code != 0 {
			t.Fatal("lock failed")
		}
		code, out, errOut := d.secrets(t, "host=github.com\n", "git-credential", "get")
		if code != 1 || out != "" || errOut != "keycell: daemon is locked, run 'keycell unlock'\n" {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})
}

// gitList returns name -> attributes of every git-credential secret.
func (d *testDaemon) gitList(t *testing.T) map[string]map[string]string {
	t.Helper()
	code, out, errOut := d.secrets(t, "", "list", "-k", gitKind, "--json")
	if code != 0 {
		t.Fatalf("list: exit %d, stderr %q", code, errOut)
	}
	var secs []secretJSON
	if err := json.Unmarshal([]byte(out), &secs); err != nil {
		t.Fatal(err)
	}
	m := map[string]map[string]string{}
	for _, s := range secs {
		m[s.Name] = s.Attributes
	}
	return m
}

func TestGitCredentialStoreAndErase(t *testing.T) {
	d := startDaemon(t)
	d.unlock(t, 0)

	run := func(t *testing.T, sub, stdin string) (string, string) {
		t.Helper()
		code, out, errOut := d.secrets(t, stdin, "git-credential", sub)
		if code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", sub, code, errOut)
		}
		return out, errOut
	}
	get := func(t *testing.T, stdin string) string {
		t.Helper()
		out, _ := run(t, "get", stdin)
		return out
	}

	t.Run("creates git/host/user with the sent fields", func(t *testing.T) {
		run(t, "store", "protocol=https\nhost=github.com\nusername=alex\npassword=tok1\n\n")
		want := map[string]string{"host": "github.com", "protocol": "https", "username": "alex"}
		if got := d.gitList(t)["git/github.com/alex"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("attributes = %v, want %v", got, want)
		}
		if out := get(t, "protocol=https\nhost=github.com\nusername=alex\n"); out != "username=alex\npassword=tok1\n" {
			t.Fatalf("get = %q", out)
		}
	})

	t.Run("creates git/host without username, path only when sent", func(t *testing.T) {
		run(t, "store", "protocol=https\nhost=gitlab.com\npath=grp/repo.git\npassword=tok2\n")
		want := map[string]string{"host": "gitlab.com", "protocol": "https", "path": "grp/repo.git"}
		if got := d.gitList(t)["git/gitlab.com"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("attributes = %v, want %v", got, want)
		}
	})

	t.Run("overwrites the match under its own name", func(t *testing.T) {
		d.mustStore(t, "work", "old", "-k", gitKind, "-a", "host=example.com", "-a", "username=me")
		run(t, "store", "protocol=https\nhost=example.com\nusername=me\npassword=renewed\n")
		list := d.gitList(t)
		if _, ok := list["git/example.com/me"]; ok {
			t.Fatal("store created a second secret instead of updating work")
		}
		if got := list["work"]; !reflect.DeepEqual(got, map[string]string{"host": "example.com", "username": "me"}) {
			t.Fatalf("attributes = %v", got)
		}
		if out := get(t, "protocol=https\nhost=example.com\nusername=me\n"); out != "username=me\npassword=renewed\n" {
			t.Fatalf("get = %q", out)
		}
	})

	t.Run("no host or no password stores nothing", func(t *testing.T) {
		before := len(d.gitList(t))
		run(t, "store", "protocol=https\npassword=x\n")
		run(t, "store", "protocol=https\nhost=nopw.example\n")
		if got := len(d.gitList(t)); got != before {
			t.Fatalf("%d secrets, want %d", got, before)
		}
	})

	t.Run("ambiguous store and erase change nothing", func(t *testing.T) {
		d.mustStore(t, "a", "va", "-k", gitKind, "-a", "host=dup.example")
		d.mustStore(t, "b", "vb", "-k", gitKind, "-a", "host=dup.example")
		_, errOut := run(t, "store", "host=dup.example\npassword=new\n")
		if errOut != "keycell: git-credential: ambiguous match: a, b, nothing stored\n" {
			t.Fatalf("store stderr = %q", errOut)
		}
		_, errOut = run(t, "erase", "host=dup.example\npassword=va\n")
		if errOut != "keycell: git-credential: ambiguous match: a, b, nothing erased\n" {
			t.Fatalf("erase stderr = %q", errOut)
		}
		list := d.gitList(t)
		if _, ok := list["a"]; !ok {
			t.Fatal("a erased")
		}
		if _, ok := list["b"]; !ok {
			t.Fatal("b erased")
		}
		if _, ok := list["git/dup.example"]; ok {
			t.Fatal("ambiguous store created git/dup.example")
		}
	})

	t.Run("erase deletes the match, no match is silent", func(t *testing.T) {
		out, errOut := run(t, "erase", "protocol=https\nhost=gitlab.com\npath=grp/repo.git\npassword=tok2\n")
		if out != "" || errOut != "" {
			t.Fatalf("erase output %q %q", out, errOut)
		}
		if _, ok := d.gitList(t)["git/gitlab.com"]; ok {
			t.Fatal("git/gitlab.com still there")
		}
		run(t, "erase", "protocol=https\nhost=nowhere.example\n")
	})

	t.Run("locked", func(t *testing.T) {
		if code, _, _ := d.exec(t, "lock"); code != 0 {
			t.Fatal("lock failed")
		}
		for _, sub := range []string{"store", "erase"} {
			code, out, errOut := d.secrets(t, "host=github.com\npassword=x\n", "git-credential", sub)
			if code != 1 || out != "" || errOut != "keycell: daemon is locked, run 'keycell unlock'\n" {
				t.Fatalf("%s: exit %d, stdout %q, stderr %q", sub, code, out, errOut)
			}
		}
	})
}
