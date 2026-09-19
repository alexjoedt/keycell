// Command keycell is the command-line client of keycelld. It talks to
// the daemon through pkg/keycell; init and passphrase are the only
// commands that touch the vault directory directly.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/internal/config"
	"github.com/alexjoedt/keycell/internal/secmem"
	"github.com/alexjoedt/keycell/internal/tty"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

func main() {
	hardenErr := secmem.Harden()
	os.Exit(run(context.Background(), os.Args, os.Getenv, os.Stdin, os.Stdout, os.Stderr, tty.Read, hardenErr))
}

// app carries the process environment so run has no globals; tests
// inject their own, prompt included.
type app struct {
	env    func(string) string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	prompt tty.ReadFunc
	cfg    *config.Config
}

// run is main without the process-global parts: Harden has already
// been called, its result comes in as hardenErr. args includes the
// program name.
func run(ctx context.Context, args []string, env func(string) string, stdin io.Reader, stdout, stderr io.Writer, prompt tty.ReadFunc, hardenErr error) int {
	switch {
	case errors.Is(hardenErr, secmem.ErrDebugDumpable):
		fmt.Fprintf(stderr, "keycell: warning: %v\n", hardenErr)
	case hardenErr != nil:
		fmt.Fprintf(stderr, "keycell: hardening failed: %v\n", hardenErr)
		return 1
	}

	a := &app{env: env, stdin: stdin, stdout: stdout, stderr: stderr, prompt: prompt}
	err := a.command().Run(ctx, args)
	var ec cli.ExitCoder
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ec):
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(stderr, msg)
		}
		return ec.ExitCode()
	default:
		fmt.Fprintf(stderr, "keycell: %v\n", err)
		return 1
	}
}

func (a *app) command() *cli.Command {
	return &cli.Command{
		Name:      "keycell",
		Usage:     "secrets for git, docker and your shell from an age-encrypted vault",
		Reader:    a.stdin,
		Writer:    a.stdout,
		ErrWriter: a.stderr,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Usage: "config file (default $XDG_CONFIG_HOME/keycell/config.json)"},
			&cli.StringFlag{Name: "socket", Usage: "socket path (default $XDG_RUNTIME_DIR/keycell/keycell.sock)"},
		},
		Before:         a.loadConfig,
		Action:         a.root,
		OnUsageError:   usageError,
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Commands: append([]*cli.Command{
			{
				Name:   "init",
				Usage:  "create the data directory, identity and an empty vault",
				Flags:  []cli.Flag{&cli.BoolFlag{Name: "no-passphrase", Usage: "store the identity unencrypted (identity.txt)"}},
				Action: a.initCmd,
			},
			{
				Name:   "passphrase",
				Usage:  "change the identity passphrase, or set one on a plain identity",
				Flags:  []cli.Flag{&cli.BoolFlag{Name: "remove", Usage: "store the identity unencrypted from now on"}},
				Action: a.passphrase,
			},
			{
				Name:   "unlock",
				Usage:  "load the identity into the daemon",
				Flags:  []cli.Flag{&cli.StringFlag{Name: "for", Usage: "auto-lock after this duration (e.g. 2h, 30m); 0 disables it for this session"}},
				Action: a.unlock,
			},
			{
				Name:   "status",
				Usage:  "show socket, lock state and identity form",
				Action: a.status,
			},
			{
				Name:   "lock",
				Usage:  "drop the identity from the daemon",
				Action: a.lock,
			},
		}, append(append(a.secretCommands(), a.transferCommands()...), append(a.gitCredentialCommands(), a.execCommands()...)...)...),
	}
}

// loadConfig resolves the four config values with flag > env > file >
// default; the CLI only overrides the socket.
func (a *app) loadConfig(ctx context.Context, cmd *cli.Command) (context.Context, error) {
	var flags config.Flags
	if cmd.IsSet("socket") {
		s := cmd.String("socket")
		flags.Socket = &s
	}
	cfg, err := config.Load(cmd.String("config"), a.env, flags)
	if err != nil {
		return ctx, cli.Exit(fmt.Sprintf("keycell: %v", err), 1)
	}
	a.cfg = cfg
	return ctx, nil
}

// root runs when no subcommand matched: help without arguments, a
// usage error with them.
func (a *app) root(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Present() {
		return cli.Exit(fmt.Sprintf("keycell: unknown command %q", cmd.Args().First()), 2)
	}
	return cli.ShowRootCommandHelp(cmd)
}

func usageError(_ context.Context, _ *cli.Command, err error, _ bool) error {
	return cli.Exit(fmt.Sprintf("keycell: %v", err), 2)
}

// noArgs rejects positional arguments for commands that take none.
func noArgs(cmd *cli.Command) error {
	if cmd.Args().Present() {
		return cli.Exit(fmt.Sprintf("keycell: %s takes no arguments", cmd.Name), 2)
	}
	return nil
}

func (a *app) connect(ctx context.Context) (*keycell.Client, error) {
	return keycell.ConnectSocket(ctx, a.cfg.Socket)
}

// exitError maps a client error to the message and exit code every
// command shares. Nil stays nil.
func exitError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keycell.ErrLocked):
		return cli.Exit("keycell: daemon is locked, run 'keycell unlock'", 1)
	case errors.Is(err, keycell.ErrNotRunning):
		return cli.Exit("keycell: daemon is not running, run 'systemctl --user start keycell'", 1)
	}
	if e, ok := errors.AsType[*keycell.Error](err); ok {
		return cli.Exit("keycell: "+e.Message, 1)
	}
	return cli.Exit("keycell: "+err.Error(), 1)
}
