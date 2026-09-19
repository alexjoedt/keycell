package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/tty"
)

// unlock loads the identity (ADR 0007: the client decrypts it) and
// hands it to the daemon. The daemon's state is checked first so an
// already unlocked daemon or a dead one never causes a prompt.
func (a *app) unlock(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	var dur *time.Duration
	if cmd.IsSet("for") {
		d, err := time.ParseDuration(cmd.String("for"))
		if err != nil || d < 0 {
			return cli.Exit(fmt.Sprintf("keycell: invalid duration %q for --for", cmd.String("for")), 2)
		}
		dur = &d
	}
	dir := a.cfg.DataDir
	form, err := identity.Detect(dir)
	switch {
	case err != nil:
		return setupError(err)
	case form == identity.FormNone:
		return cli.Exit("keycell: no identity, run 'keycell init'", 1)
	}

	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		return exitError(err)
	}
	if !st.Locked {
		fmt.Fprintf(a.stdout, "already %s\n", lockState(st, time.Now()))
		return nil
	}

	send := func(id []byte) error {
		if dur != nil {
			return c.UnlockFor(ctx, id, *dur)
		}
		return c.Unlock(ctx, id)
	}
	if form == identity.FormPlain {
		var id []byte
		if id, err = identity.LoadFile(filepath.Join(dir, identity.PlainFile), nil); err != nil {
			return setupError(err)
		}
		err = send(id)
	} else {
		path := filepath.Join(dir, identity.EncryptedFile)
		err = a.askPassphrase("Passphrase: ", func(pass []byte) error {
			id, err := identity.LoadFile(path, pass)
			if err != nil {
				return err
			}
			return send(id)
		})
	}
	switch {
	case err == nil:
	case errors.Is(err, identity.ErrWrongPassphrase), errors.Is(err, tty.ErrNoTTY),
		errors.Is(err, tty.ErrInterrupted), errors.Is(err, identity.ErrMalformed):
		return setupError(err)
	default:
		return exitError(err)
	}

	if st, err = c.Status(ctx); err != nil {
		return exitError(err)
	}
	fmt.Fprintln(a.stdout, lockState(st, time.Now()))
	return nil
}
