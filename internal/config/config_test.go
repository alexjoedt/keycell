package config

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000"}
	withEnv := func(kv ...string) map[string]string {
		m := map[string]string{}
		maps.Copy(m, base)
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	tests := []struct {
		name    string
		path    string
		env     map[string]string
		flags   Flags
		want    Config
		wantErr string
	}{
		{
			name: "defaults",
			env:  base,
			want: Config{DataDir: "/home/u/.local/share/keycell", Socket: "/run/user/1000/keycell/keycell.sock", AutoLock: 8 * time.Hour, LogLevel: "info"},
		},
		{
			name: "xdg dirs",
			env:  withEnv("XDG_DATA_HOME", "/data", "XDG_CONFIG_HOME", t.TempDir()),
			want: Config{DataDir: "/data/keycell", Socket: "/run/user/1000/keycell/keycell.sock", AutoLock: 8 * time.Hour, LogLevel: "info"},
		},
		{
			name: "default file from xdg config home",
			env:  withEnv("XDG_CONFIG_HOME", filepath.Dir(filepath.Dir(write("cfg/keycell/config.json", `{"log_level":"debug"}`)))),
			want: Config{DataDir: "/home/u/.local/share/keycell", Socket: "/run/user/1000/keycell/keycell.sock", AutoLock: 8 * time.Hour, LogLevel: "debug"},
		},
		{
			name: "file sets all four",
			path: write("all.json", `{"data_dir":"~/kc","socket":"/tmp/kc.sock","auto_lock":"30m","log_level":"WARN"}`),
			env:  base,
			want: Config{DataDir: "/home/u/kc", Socket: "/tmp/kc.sock", AutoLock: 30 * time.Minute, LogLevel: "warn"},
		},
		{
			name: "env overrides file",
			path: write("env.json", `{"data_dir":"/file","auto_lock":"30m"}`),
			env:  withEnv(EnvDataDir, "/env", EnvAutoLock, "0", EnvLogLevel, "error"),
			want: Config{DataDir: "/env", Socket: "/run/user/1000/keycell/keycell.sock", AutoLock: 0, LogLevel: "error"},
		},
		{
			name:  "flag overrides env and file",
			path:  write("flag.json", `{"socket":"/file.sock","log_level":"debug"}`),
			env:   withEnv(EnvSocket, "/env.sock", EnvDataDir, "/env"),
			flags: Flags{Socket: new("/flag.sock"), AutoLock: new("1h")},
			want:  Config{DataDir: "/env", Socket: "/flag.sock", AutoLock: time.Hour, LogLevel: "debug"},
		},
		{
			name: "file path from env",
			env:  withEnv(EnvConfig, write("fromenv.json", `{"auto_lock":"2h"}`)),
			want: Config{DataDir: "/home/u/.local/share/keycell", Socket: "/run/user/1000/keycell/keycell.sock", AutoLock: 2 * time.Hour, LogLevel: "info"},
		},
		{
			name: "socket from file needs no runtime dir",
			path: write("sock.json", `{"socket":"/s.sock"}`),
			env:  map[string]string{"HOME": "/home/u"},
			want: Config{DataDir: "/home/u/.local/share/keycell", Socket: "/s.sock", AutoLock: 8 * time.Hour, LogLevel: "info"},
		},
		{name: "missing runtime dir", env: map[string]string{"HOME": "/home/u"}, wantErr: "XDG_RUNTIME_DIR is not set"},
		{name: "missing home", env: map[string]string{"XDG_RUNTIME_DIR": "/run"}, wantErr: "neither XDG_CONFIG_HOME nor HOME"},
		{name: "explicit file missing", path: filepath.Join(dir, "nope.json"), env: base, wantErr: "nope.json"},
		{name: "unknown key", path: write("unknown.json", `{"sockett":"/x"}`), env: base, wantErr: `unknown.json: json: unknown field "sockett"`},
		{name: "invalid json", path: write("bad.json", `{`), env: base, wantErr: "bad.json"},
		{name: "trailing data", path: write("trail.json", `{} {}`), env: base, wantErr: "trailing data"},
		{name: "relative path in file", path: write("rel.json", `{"data_dir":"kc"}`), env: base, wantErr: `rel.json: key data_dir: path "kc" is not absolute`},
		{name: "tilde without home", path: write("tilde.json", `{"data_dir":"~/kc"}`), env: map[string]string{"XDG_RUNTIME_DIR": "/run", "XDG_CONFIG_HOME": "/c"}, wantErr: "HOME is not set"},
		{name: "var not expanded", env: withEnv(EnvSocket, "$XDG_RUNTIME_DIR/s.sock"), wantErr: "KEYCELL_SOCKET: path \"$XDG_RUNTIME_DIR/s.sock\" is not absolute"},
		{name: "bad duration in env", env: withEnv(EnvAutoLock, "8 hours"), wantErr: `KEYCELL_AUTO_LOCK: invalid duration "8 hours"`},
		{name: "negative duration", env: base, flags: Flags{AutoLock: new("-1h")}, wantErr: `--auto-lock: duration "-1h" is negative`},
		{name: "bad log level in flag", env: base, flags: Flags{LogLevel: new("loud")}, wantErr: `--log-level: invalid log level "loud"`},
		{name: "bad log level in file", path: write("lvl.json", `{"log_level":"loud"}`), env: base, wantErr: "lvl.json: key log_level"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(tt.path, func(k string) string { return tt.env[k] }, tt.flags)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if *got != tt.want {
				t.Fatalf("got %+v\nwant %+v", *got, tt.want)
			}
		})
	}
}
