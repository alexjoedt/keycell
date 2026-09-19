package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// gitRunner runs git detached from the terminal with a private global
// config, so the only credential source is the keycell helper.
type gitRunner struct {
	t   *testing.T
	env []string
}

func (g *gitRunner) run(dir, stdin string, args ...string) (int, string, string) {
	g.t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = g.env
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		g.t.Fatalf("git %v: %v", args, err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

func (g *gitRunner) must(dir string, args ...string) string {
	g.t.Helper()
	code, out, errOut := g.run(dir, "", args...)
	if code != 0 {
		g.t.Fatalf("git %v: exit %d\n%s", args, code, errOut)
	}
	return out
}

// gitHTTPBackend serves the bare repositories under root over TLS with
// HTTP basic auth in front of git's own CGI backend.
func gitHTTPBackend(t *testing.T, root, user, password string) *httptest.Server {
	t.Helper()
	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skipf("no git-http-backend: %v", err)
	}
	cgiHandler := &cgi.Handler{
		Path: backend,
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="keycell e2e"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		cgiHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitCredentialEndToEnd(t *testing.T) {
	const user, token = "alex", "ghp_e2e_t0ken"
	repos := t.TempDir()
	srv := gitHTTPBackend(t, repos, user, token)
	host := strings.TrimPrefix(srv.URL, "https://")

	bin, daemonBin := buildBinaries(t)
	dataDir := t.TempDir()
	socket := filepath.Join(t.TempDir(), "keycell.sock")
	startDaemonProcess(t, daemonBin, socket, dataDir)
	e := &e2e{t: t, bin: bin, socket: socket, dataDir: dataDir}
	e.expect(0, "", unencryptedWarning, "init", "--no-passphrase")
	e.expect(0, "unlocked, no auto-lock\n", "", "unlock")

	caFile := filepath.Join(dataDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	gitConfig := filepath.Join(dataDir, "gitconfig")
	config := "[credential]\n\thelper = \"" + bin + " git-credential\"\n" +
		"[http]\n\tsslCAInfo = " + caFile + "\n" +
		"[user]\n\tname = e2e\n\temail = e2e@example.com\n" +
		"[init]\n\tdefaultBranch = main\n"
	if err := os.WriteFile(gitConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &gitRunner{t: t, env: e2eEnv(socket, dataDir,
		"GIT_CONFIG_GLOBAL="+gitConfig, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")}

	remote := filepath.Join(repos, "repo.git")
	g.must("", "init", "--bare", remote)
	g.must(remote, "config", "http.receivepack", "true")

	// Clone, push and pull with the token only in the vault.
	e.expectIn(dataDir, token+"\n", 0, "", "", "store", "git/"+host, "-k", gitKind, "-a", "host="+host, "-a", "username="+user)
	work := filepath.Join(t.TempDir(), "work")
	g.must("", "clone", srv.URL+"/repo.git", work)
	if err := os.WriteFile(filepath.Join(work, "README"), []byte("keycell\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.must(work, "add", "README")
	g.must(work, "commit", "-q", "-m", "add README")
	g.must(work, "push", "-q", "origin", "HEAD:main")
	g.must(work, "pull", "-q", "origin", "main")
	if out := g.must(remote, "log", "--oneline", "main"); !strings.Contains(out, "add README") {
		t.Fatalf("remote log: %q", out)
	}
	for _, f := range []string{gitConfig, filepath.Join(work, ".git", "config")} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(token)) {
			t.Fatalf("%s contains the token", f)
		}
	}

	// An unknown host gets nothing from keycell, so git falls back to
	// its (disabled) prompt.
	code, out, errOut := g.run("", "protocol=https\nhost=unknown.example\n\n", "credential", "fill")
	if code == 0 || out != "" || !strings.Contains(errOut, "terminal prompts disabled") {
		t.Fatalf("fill unknown host: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	// approve stores, reject erases.
	cred := "protocol=https\nhost=other.example\nusername=bob\npassword=pw-bob\n\n"
	if code, _, errOut := g.run("", cred, "credential", "approve"); code != 0 {
		t.Fatalf("approve: exit %d, stderr %q", code, errOut)
	}
	e.expect(0, "git/"+host+"\ngit/other.example/bob\n", "", "list", "-k", gitKind)
	e.expectIn(dataDir, "protocol=https\nhost=other.example\nusername=bob\n", 0, "username=bob\npassword=pw-bob\n", "", "git-credential", "get")
	if code, _, errOut := g.run("", cred, "credential", "reject"); code != 0 {
		t.Fatalf("reject: exit %d, stderr %q", code, errOut)
	}
	e.expect(0, "git/"+host+"\n", "", "list", "-k", gitKind)

	// Locked daemon: the helper's message reaches git's stderr.
	e.expect(0, "", "", "lock")
	code, out, errOut = g.run("", "protocol=https\nhost="+host+"\n\n", "credential", "fill")
	if code == 0 || out != "" || !strings.Contains(errOut, "keycell: daemon is locked, run 'keycell unlock'") {
		t.Fatalf("fill locked: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}
