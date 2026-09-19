// Command keycelld is the keycell daemon. It runs in the foreground,
// serves the protocol on a unix socket and is meant to be started by
// the systemd user unit in contrib/keycell.service (Type=notify).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/alexjoedt/log"

	"github.com/alexjoedt/keycell/internal/config"
	"github.com/alexjoedt/keycell/internal/daemon"
	"github.com/alexjoedt/keycell/internal/secmem"
	"github.com/alexjoedt/keycell/internal/vault"
)

func main() {
	hardenErr := secmem.Harden()
	os.Exit(run(os.Args[1:], os.Getenv, os.Stderr, hardenErr))
}

// run is main without the process-global parts: Harden has already
// been called, its result comes in as hardenErr.
func run(args []string, env func(string) string, stderr io.Writer, hardenErr error) int {
	fs := flag.NewFlagSet("keycelld", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "config file (default $XDG_CONFIG_HOME/keycell/config.json)")
	fs.String("data-dir", "", "vault directory (default $XDG_DATA_HOME/keycell)")
	fs.String("socket", "", "socket path (default $XDG_RUNTIME_DIR/keycell/keycell.sock)")
	fs.String("auto-lock", "", "lock after this duration, 0 disables (default 8h)")
	fs.String("log-level", "", "trace, debug, info, warn or error (default info)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	var flags config.Flags
	fs.Visit(func(f *flag.Flag) {
		v := f.Value.String()
		switch f.Name {
		case "data-dir":
			flags.DataDir = &v
		case "socket":
			flags.Socket = &v
		case "auto-lock":
			flags.AutoLock = &v
		case "log-level":
			flags.LogLevel = &v
		}
	})
	cfg, err := config.Load(*configPath, env, flags)
	if err != nil {
		fmt.Fprintf(stderr, "keycelld: %v\n", err)
		return 1
	}

	logger := log.New(
		log.WithLevel(log.ParseLogLevel(cfg.LogLevel)),
		log.WithWriter(stderr),
	).Slog()

	switch {
	case errors.Is(hardenErr, secmem.ErrDebugDumpable):
		logger.Warn("process is dumpable", "err", hardenErr)
	case hardenErr != nil:
		logger.Error("hardening failed", "err", hardenErr)
		return 1
	}

	logger.Info("starting keycelld",
		"data_dir", cfg.DataDir,
		"socket", cfg.Socket,
		"auto_lock", cfg.AutoLock,
		"log_level", cfg.LogLevel,
	)

	vaultPath := filepath.Join(cfg.DataDir, vault.File)
	if _, err := os.Stat(vaultPath); err != nil {
		logger.Info("no vault found, starting locked; run `keycell init` to create one", "path", vaultPath)
	}

	session := daemon.NewSession(logger, cfg.AutoLock)
	store := daemon.NewStore(vaultPath, session, logger)
	srv := daemon.NewServer(session, store, logger)

	ln, err := daemon.Listen(cfg.Socket)
	if err != nil {
		logger.Error("listen failed", "err", err)
		return 1
	}

	signal.Ignore(syscall.SIGHUP)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	notify(env("NOTIFY_SOCKET"), "READY=1", logger)
	logger.Info("listening", "socket", cfg.Socket)

	err = srv.Serve(ctx, ln)
	notify(env("NOTIFY_SOCKET"), "STOPPING=1", logger)
	if err != nil {
		logger.Error("serve failed", "err", err)
		return 1
	}
	logger.Info("stopped")
	return 0
}

// notify sends one sd_notify state to systemd; without NOTIFY_SOCKET
// it does nothing. A failure is logged, never fatal.
func notify(socket, state string, logger *slog.Logger) {
	if socket == "" {
		return
	}
	if err := sdNotify(socket, state); err != nil {
		logger.Warn("sd_notify failed", "state", state, "err", err)
	}
}
