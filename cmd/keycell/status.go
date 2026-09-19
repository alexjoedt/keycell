package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

// status prints what the user can check by hand: the socket, the
// identity form on disk (the daemon does not know it, ADR 0007) and the
// daemon's lock state. A daemon that is not running is reported on
// stdout after the other two lines and ends with exit 1.
func (a *app) status(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "socket:   %s\n", a.cfg.Socket)
	fmt.Fprintf(a.stdout, "identity: %s\n", identityForm(a.cfg.DataDir))

	st, err := a.daemonStatus(ctx)
	switch {
	case errors.Is(err, keycell.ErrNotRunning):
		fmt.Fprintln(a.stdout, "daemon:   not running, run 'systemctl --user start keycell'")
		return cli.Exit("", 1)
	case err != nil:
		return exitError(err)
	}
	fmt.Fprintf(a.stdout, "daemon:   %s\n", lockState(st, time.Now()))
	return nil
}

func (a *app) daemonStatus(ctx context.Context) (keycell.Status, error) {
	c, err := a.connect(ctx)
	if err != nil {
		return keycell.Status{}, err
	}
	return c.Status(ctx)
}

func identityForm(dataDir string) string {
	form, err := identity.Detect(dataDir)
	switch {
	case errors.Is(err, identity.ErrAmbiguous):
		return "ambiguous, both identity.age and identity.txt exist"
	case err != nil:
		return err.Error()
	}
	switch form {
	case identity.FormEncrypted:
		return "passphrase-protected"
	case identity.FormPlain:
		return "UNENCRYPTED"
	case identity.FormNone:
		return "none, run 'keycell init'"
	}
	return string(form)
}

func lockState(st keycell.Status, now time.Time) string {
	switch {
	case st.Locked:
		return "locked"
	case st.LocksAt.IsZero():
		return "unlocked, no auto-lock"
	}
	return "unlocked, locks in " + formatRemaining(st.LocksAt.Sub(now))
}

// formatRemaining renders a duration the way unlock and status agree
// on: whole minutes, "<1m" below that.
func formatRemaining(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Minute {
		return "<1m"
	}
	h, m := d/time.Hour, (d%time.Hour)/time.Minute
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

func (a *app) lock(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	return exitError(c.Lock(ctx))
}
