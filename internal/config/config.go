// Package config resolves the four settings keycelld and keycell share:
// where the vault lives, where the socket is, when to auto-lock and how
// much to log. Precedence is flag > environment > file > default, each
// layer overriding only what it sets (wayfinder ticket 08).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Config is the effective configuration.
type Config struct {
	DataDir  string
	Socket   string
	AutoLock time.Duration // 0 disables auto-lock
	LogLevel string
}

// Flags are command-line overrides; a nil field is "not given".
// AutoLock uses time.ParseDuration syntax, "0" disables auto-lock.
type Flags struct {
	DataDir  *string
	Socket   *string
	AutoLock *string
	LogLevel *string
}

// Environment variable names.
const (
	EnvConfig   = "KEYCELL_CONFIG"
	EnvDataDir  = "KEYCELL_DATA_DIR"
	EnvSocket   = "KEYCELL_SOCKET"
	EnvAutoLock = "KEYCELL_AUTO_LOCK"
	EnvLogLevel = "KEYCELL_LOG_LEVEL"
)

// Defaults for the values that need none from the environment.
const (
	DefaultAutoLock = 8 * time.Hour
	DefaultLogLevel = "info"
)

// ErrNoRuntimeDir: the socket default needs $XDG_RUNTIME_DIR; there is
// deliberately no /tmp fallback.
var ErrNoRuntimeDir = errors.New("XDG_RUNTIME_DIR is not set; set it, or set the socket path via " + EnvSocket + ", --socket or the config file")

var logLevels = []string{"trace", "debug", "info", "warn", "error"}

// layer is one source of settings; every field is optional.
type layer struct {
	DataDir  *string `json:"data_dir"`
	Socket   *string `json:"socket"`
	AutoLock *string `json:"auto_lock"`
	LogLevel *string `json:"log_level"`
}

// Load resolves the configuration. path is the --config flag ("" when
// not given), env looks up environment variables (os.Getenv in
// production, a map in tests). An explicitly named file that does not
// exist is an error; a missing default file means defaults.
func Load(path string, env func(string) string, flags Flags) (*Config, error) {
	c := &Config{AutoLock: DefaultAutoLock, LogLevel: DefaultLogLevel}
	home := env("HOME")

	path, explicit, err := configPath(path, env)
	if err != nil {
		return nil, err
	}
	file, err := readFile(path, explicit)
	if err != nil {
		return nil, err
	}
	if err := c.apply(file, home, func(key string) string { return path + ": key " + key }); err != nil {
		return nil, err
	}

	envLayer := layer{
		DataDir:  envValue(env, EnvDataDir),
		Socket:   envValue(env, EnvSocket),
		AutoLock: envValue(env, EnvAutoLock),
		LogLevel: envValue(env, EnvLogLevel),
	}
	if err := c.apply(envLayer, home, func(key string) string { return "KEYCELL_" + strings.ToUpper(key) }); err != nil {
		return nil, err
	}

	if err := c.apply(layer(flags), home, func(key string) string { return "--" + strings.ReplaceAll(key, "_", "-") }); err != nil {
		return nil, err
	}

	if c.DataDir == "" {
		c.DataDir, err = xdgDir(env, "XDG_DATA_HOME", ".local/share")
		if err != nil {
			return nil, err
		}
	}
	if c.Socket == "" {
		rt := env("XDG_RUNTIME_DIR")
		if rt == "" {
			return nil, fmt.Errorf("config: %w", ErrNoRuntimeDir)
		}
		c.Socket = filepath.Join(rt, "keycell", "keycell.sock")
	}
	return c, nil
}

func configPath(flag string, env func(string) string) (path string, explicit bool, err error) {
	switch {
	case flag != "":
		path, err = expandPath(flag, env("HOME"))
		return path, true, wrapKey(err, "--config")
	case env(EnvConfig) != "":
		path, err = expandPath(env(EnvConfig), env("HOME"))
		return path, true, wrapKey(err, EnvConfig)
	}
	dir, err := xdgDir(env, "XDG_CONFIG_HOME", ".config")
	if err != nil {
		return "", false, err
	}
	return filepath.Join(dir, "config.json"), false, nil
}

func readFile(path string, explicit bool) (layer, error) {
	var l layer
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return l, nil
		}
		return l, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return l, fmt.Errorf("config: %s: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return l, fmt.Errorf("config: %s: trailing data after document", path)
	}
	return l, nil
}

// apply overrides c with the set fields of l. where turns a JSON key
// into the name of its source for error messages.
func (c *Config) apply(l layer, home string, where func(key string) string) error {
	if l.DataDir != nil {
		p, err := expandPath(*l.DataDir, home)
		if err != nil {
			return wrapKey(err, where("data_dir"))
		}
		c.DataDir = p
	}
	if l.Socket != nil {
		p, err := expandPath(*l.Socket, home)
		if err != nil {
			return wrapKey(err, where("socket"))
		}
		c.Socket = p
	}
	if l.AutoLock != nil {
		d, err := parseAutoLock(*l.AutoLock)
		if err != nil {
			return wrapKey(err, where("auto_lock"))
		}
		c.AutoLock = d
	}
	if l.LogLevel != nil {
		lv, err := parseLogLevel(*l.LogLevel)
		if err != nil {
			return wrapKey(err, where("log_level"))
		}
		c.LogLevel = lv
	}
	return nil
}

func parseAutoLock(s string) (time.Duration, error) {
	if s == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %q is negative", s)
	}
	return d, nil
}

func parseLogLevel(s string) (string, error) {
	lv := strings.ToLower(strings.TrimSpace(s))
	if slices.Contains(logLevels, lv) {
		return lv, nil
	}
	return "", fmt.Errorf("invalid log level %q, want one of %s", s, strings.Join(logLevels, ", "))
}

// expandPath expands a leading "~/" with home and requires an absolute
// result. "$VAR" is not expanded.
func expandPath(p, home string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home == "" {
			return "", fmt.Errorf("cannot expand %q, HOME is not set", p)
		}
		p = filepath.Join(home, p[1:])
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q is not absolute", p)
	}
	return filepath.Clean(p), nil
}

func xdgDir(env func(string) string, xdg, fallback string) (string, error) {
	if dir := env(xdg); dir != "" {
		return filepath.Join(dir, "keycell"), nil
	}
	home := env("HOME")
	if home == "" {
		return "", fmt.Errorf("config: neither %s nor HOME is set", xdg)
	}
	return filepath.Join(home, fallback, "keycell"), nil
}

func envValue(env func(string) string, name string) *string {
	if v := env(name); v != "" {
		return &v
	}
	return nil
}

func wrapKey(err error, where string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("config: %s: %w", where, err)
}
