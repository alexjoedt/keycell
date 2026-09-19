package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// e2e drives the built helper, keycell and docker binaries against a
// keycelld process. Every command runs in its own session (Setsid),
// so no /dev/tty is available, as under docker's own exec.
type e2e struct {
	t      *testing.T
	bin    string
	socket string
	env    []string
}

// buildBinaries builds the helper, keycell and keycelld into one
// directory, so the directory can go on docker's PATH.
func buildBinaries(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, b := range []struct{ name, pkg string }{{prog, "."}, {"keycell", "../keycell"}, {"keycelld", "../keycelld"}} {
		out, err := exec.Command("go", "build", "-o", filepath.Join(dir, b.name), b.pkg).CombinedOutput()
		if err != nil {
			t.Skipf("go build %s: %v\n%s", b.name, err, out)
		}
	}
	return dir
}

// startE2E builds the binaries, starts keycelld on a temporary socket,
// initializes and unlocks a plain-identity vault through the keycell
// binary and returns a runner whose PATH starts with the binaries.
func startE2E(t *testing.T) *e2e {
	t.Helper()
	bin := buildBinaries(t)
	dataDir := t.TempDir()
	socket := filepath.Join(t.TempDir(), "keycell.sock")
	env := []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + dataDir,
		"XDG_CONFIG_HOME=" + filepath.Join(dataDir, "xdg-config"),
		"KEYCELL_SOCKET=" + socket,
		"KEYCELL_DATA_DIR=" + dataDir,
	}
	startDaemonProcess(t, filepath.Join(bin, "keycelld"), socket, env)
	e := &e2e{t: t, bin: bin, socket: socket, env: env}
	for _, args := range [][]string{{"keycell", "init", "--no-passphrase"}, {"keycell", "unlock"}} {
		if code, out, errOut := e.run("", args...); code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, out, errOut)
		}
	}
	return e
}

func startDaemonProcess(t *testing.T, bin, socket string, env []string) {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Env = append(append([]string{}, env...), "KEYCELL_AUTO_LOCK=0")
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", socket); err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("keycelld did not listen on %s within 5s\n%s", socket, stderr.String())
}

// run executes a command from PATH detached from the terminal with the
// e2e environment and returns exit code, stdout and stderr.
func (e *e2e) run(stdin string, args ...string) (int, string, string) {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// exec resolves the program through the test's own PATH, so the
	// built binaries are addressed by path; docker finds the helper
	// through the PATH in cmd.Env.
	name := args[0]
	if _, err := os.Stat(filepath.Join(e.bin, name)); err == nil {
		name = filepath.Join(e.bin, name)
	}
	cmd := exec.CommandContext(ctx, name, args[1:]...)
	cmd.Env = e.env
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		e.t.Fatalf("%v: %v", args, err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

// expect runs the command and checks exit code, exact stdout, and that
// stderr contains wantErr.
func (e *e2e) expect(code int, wantOut, wantErr string, args ...string) {
	e.t.Helper()
	e.expectIn("", code, wantOut, wantErr, args...)
}

func (e *e2e) expectIn(stdin string, code int, wantOut, wantErr string, args ...string) {
	e.t.Helper()
	got, out, errOut := e.run(stdin, args...)
	if got != code || out != wantOut || !strings.Contains(errOut, wantErr) {
		e.t.Fatalf("%v: exit %d, stdout %q, stderr %q; want exit %d, stdout %q, stderr containing %q",
			args, got, out, errOut, code, wantOut, wantErr)
	}
}

// TestProtocolEndToEnd talks to the built helper the way docker does:
// one argument, request on stdin, answer on stdout.
func TestProtocolEndToEnd(t *testing.T) {
	e := startE2E(t)
	const server = "https://index.docker.io/v1/"

	e.expectIn(login(server, "alex", "s3cret"), 0, "", "", prog, "store")
	e.expect(0, "docker/index.docker.io\n", "", "keycell", "list", "-k", "docker-registry")
	e.expectIn(server, 0, `{"ServerURL":"https://index.docker.io/v1/","Username":"alex","Secret":"s3cret"}`+"\n", "", prog, "get")
	e.expect(0, `{"https://index.docker.io/v1/":"alex"}`+"\n", "", prog, "list")
	e.expectIn("ghcr.io", 1, notFound+"\n", "", prog, "get")
	e.expectIn(server, 0, "", "", prog, "erase")
	e.expect(0, "{}\n", "", prog, "list")
	e.expectIn(server, 1, notFound+"\n", "", prog, "get")
	e.expect(1, "", "usage: "+prog, prog)

	e.expect(0, "", "", "keycell", "lock")
	e.expectIn(server, 1, "", locked, prog, "get")
	e.expect(0, "{}\n", locked, prog, "list")
}

// TestDockerEndToEnd runs docker login, pull and logout with
// "credsStore": "keycell" against a minimal private registry. It needs
// the docker CLI and a daemon that can reach 127.0.0.1 on this host.
func TestDockerEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker daemon not reachable: %v\n%s", err, out)
	}

	e := startE2E(t)
	const user, password = "alex", "s3cret"
	reg := httptest.NewServer(registry(t, user, password))
	t.Cleanup(reg.Close)
	server := strings.TrimPrefix(reg.URL, "http://")
	image := server + "/keycell/e2e:latest"

	dockerConfig := t.TempDir()
	if err := os.WriteFile(filepath.Join(dockerConfig, "config.json"), []byte(`{"credsStore":"keycell"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.env = append(e.env, "DOCKER_CONFIG="+dockerConfig)
	t.Cleanup(func() { _, _, _ = e.run("", "docker", "rmi", "-f", image) })

	if code, out, errOut := e.run(password, "docker", "login", server, "-u", user, "--password-stdin"); code != 0 {
		t.Fatalf("docker login: exit %d\n%s%s", code, out, errOut)
	}
	e.expect(0, "docker/"+server+"\n", "", "keycell", "list", "-k", "docker-registry")
	cfg, err := os.ReadFile(filepath.Join(dockerConfig, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cfg, []byte(password)) || bytes.Contains(cfg, []byte(`"auth"`)) {
		t.Fatalf("config.json holds credentials:\n%s", cfg)
	}

	if code, out, errOut := e.run("", "docker", "pull", image); code != 0 {
		t.Fatalf("docker pull: exit %d\n%s%s", code, out, errOut)
	}

	if code, out, errOut := e.run("", "docker", "logout", server); code != 0 {
		t.Fatalf("docker logout: exit %d\n%s%s", code, out, errOut)
	}
	e.expect(0, "", "", "keycell", "list", "-k", "docker-registry")
	_, _, _ = e.run("", "docker", "rmi", "-f", image)
	if code, out, errOut := e.run("", "docker", "pull", image); code == 0 || !strings.Contains(errOut, "auth") {
		t.Fatalf("docker pull after logout: exit %d\n%s%s", code, out, errOut)
	}

	if code, out, errOut := e.run(password, "docker", "login", server, "-u", user, "--password-stdin"); code != 0 {
		t.Fatalf("docker login again: exit %d\n%s%s", code, out, errOut)
	}
	e.expect(0, "", "", "keycell", "lock")
	if code, out, errOut := e.run("", "docker", "pull", image); code == 0 || !strings.Contains(errOut, strings.TrimSpace(locked)) {
		t.Fatalf("docker pull while locked: exit %d\n%s%s", code, out, errOut)
	}
}

// registry serves one image, keycell/e2e:latest, over the v2 API behind
// HTTP basic auth: an empty layer and a config for the host platform.
func registry(t *testing.T, user, password string) http.Handler {
	t.Helper()
	var tarBuf bytes.Buffer
	if err := tar.NewWriter(&tarBuf).Close(); err != nil {
		t.Fatal(err)
	}
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	if _, err := gz.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(map[string]any{
		"architecture": runtime.GOARCH,
		"os":           "linux",
		"created":      "2026-01-01T00:00:00Z",
		"config":       map[string]any{},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{digest(tarBuf.Bytes())}},
	})
	const (
		manifestType = "application/vnd.docker.distribution.manifest.v2+json"
		configType   = "application/vnd.docker.container.image.v1+json"
		layerType    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	)
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     manifestType,
		"config":        map[string]any{"mediaType": configType, "size": len(config), "digest": digest(config)},
		"layers":        []map[string]any{{"mediaType": layerType, "size": layer.Len(), "digest": digest(layer.Bytes())}},
	})
	blobs := map[string][]byte{digest(config): config, digest(layer.Bytes()): layer.Bytes()}

	serve := func(w http.ResponseWriter, r *http.Request, contentType string, body []byte) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Docker-Content-Digest", digest(body))
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="e2e"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`))
			return
		}
		switch p := r.URL.Path; {
		case p == "/v2/":
			serve(w, r, "application/json", []byte("{}"))
		case p == "/v2/keycell/e2e/manifests/latest", p == "/v2/keycell/e2e/manifests/"+digest(manifest):
			serve(w, r, manifestType, manifest)
		case strings.HasPrefix(p, "/v2/keycell/e2e/blobs/") && blobs[strings.TrimPrefix(p, "/v2/keycell/e2e/blobs/")] != nil:
			serve(w, r, "application/octet-stream", blobs[strings.TrimPrefix(p, "/v2/keycell/e2e/blobs/")])
		default:
			http.NotFound(w, r)
		}
	})
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
