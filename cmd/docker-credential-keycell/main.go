// Command docker-credential-keycell is the credential helper docker
// calls when ~/.docker/config.json names "credsStore": "keycell". It
// speaks the docker-credential-helpers protocol on stdin and stdout and
// keeps registry logins in keycelld as secrets of kind docker-registry.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alexjoedt/keycell/internal/config"
	"github.com/alexjoedt/keycell/internal/secmem"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

const (
	prog = "docker-credential-keycell"
	kind = "docker-registry"
)

func main() {
	hardenErr := secmem.Harden()
	os.Exit(run(context.Background(), os.Args, os.Getenv, os.Stdin, os.Stdout, os.Stderr, hardenErr))
}

// helper carries the process environment so run has no globals; tests
// inject their own.
type helper struct {
	env    func(string) string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// run is main without the process-global parts: Harden has already
// been called, its result comes in as hardenErr. args includes the
// program name; docker passes exactly one argument.
func run(ctx context.Context, args []string, env func(string) string, stdin io.Reader, stdout, stderr io.Writer, hardenErr error) int {
	switch {
	case errors.Is(hardenErr, secmem.ErrDebugDumpable):
		fmt.Fprintf(stderr, "%s: warning: %v\n", prog, hardenErr)
	case hardenErr != nil:
		fmt.Fprintf(stderr, "%s: hardening failed: %v\n", prog, hardenErr)
		return 1
	}

	h := &helper{env: env, stdin: stdin, stdout: stdout, stderr: stderr}
	var err error
	switch {
	case len(args) != 2:
		err = errUsage
	default:
		switch args[1] {
		case "get":
			err = h.get(ctx)
		case "store":
			err = h.store(ctx)
		case "erase":
			err = h.erase(ctx)
		case "list":
			err = h.list(ctx)
		default:
			err = errUsage
		}
	}

	var ec *exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ec):
		if ec.msg != "" {
			fmt.Fprintln(stderr, ec.msg)
		}
		return ec.code
	default:
		fmt.Fprintf(stderr, "%s: %v\n", prog, err)
		return 1
	}
}

// exitError ends a command with a message on stderr (empty for none)
// and an exit code.
type exitError struct {
	msg  string
	code int
}

func (e *exitError) Error() string { return e.msg }

func exitf(format string, args ...any) error {
	return &exitError{msg: prog + ": " + fmt.Sprintf(format, args...), code: 1}
}

var errUsage = &exitError{msg: "usage: " + prog + " <get|store|erase|list>", code: 1}

// connect resolves the socket like the CLI ($KEYCELL_SOCKET, config
// file, $XDG_RUNTIME_DIR) and checks that a daemon answers.
func (h *helper) connect(ctx context.Context) (*keycell.Client, error) {
	cfg, err := config.Load("", h.env, config.Flags{})
	if err != nil {
		return nil, err
	}
	return keycell.ConnectSocket(ctx, cfg.Socket)
}

// daemonError maps a client error to the message and exit code every
// command shares; ambiguous matches are the helper's own. Nil stays nil.
func daemonError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keycell.ErrLocked):
		return exitf("daemon is locked, run 'keycell unlock'")
	case errors.Is(err, keycell.ErrNotRunning):
		return exitf("daemon is not running, run 'systemctl --user start keycell'")
	}
	if e, ok := errors.AsType[*ambiguousError](err); ok {
		return exitf("%v", e)
	}
	if e, ok := errors.AsType[*keycell.Error](err); ok {
		return exitf("%s", e.Message)
	}
	return exitf("%v", err)
}
