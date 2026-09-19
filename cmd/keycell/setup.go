package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/internal/identity"
)

// passphraseAttempts is how often a wrong passphrase may be retried
// before the command gives up; unlock shares the number.
const passphraseAttempts = 3

const unencryptedWarning = "keycell: warning: identity is stored unencrypted; anyone with read access to identity.txt can decrypt the vault"

// initCmd creates the data directory, identity and empty vault. It
// never talks to the daemon.
func (a *app) initCmd(_ context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	var pass []byte
	if !cmd.Bool("no-passphrase") {
		var err error
		if pass, err = a.prompt.Confirm("New passphrase: "); err != nil {
			return promptError(err)
		}
	}
	if err := identity.Init(a.cfg.DataDir, pass); err != nil {
		return setupError(err)
	}
	fmt.Fprintf(a.stdout, "initialized %s\n", a.cfg.DataDir)
	fmt.Fprintln(a.stdout, "start the daemon:  systemctl --user enable --now keycell")
	fmt.Fprintln(a.stdout, "load the identity: keycell unlock")
	if pass == nil {
		fmt.Fprintln(a.stderr, unencryptedWarning)
	}
	return nil
}

// passphrase changes, sets or removes the passphrase on the identity
// file. A running, unlocked daemon is unaffected (ADR 0007).
func (a *app) passphrase(_ context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	dir := a.cfg.DataDir
	form, err := identity.Detect(dir)
	if err != nil {
		return setupError(err)
	}
	remove := cmd.Bool("remove")
	switch {
	case form == identity.FormNone:
		return cli.Exit("keycell: no identity, run 'keycell init'", 1)
	case remove && form == identity.FormPlain:
		return cli.Exit("keycell: identity is not passphrase-protected", 1)
	case remove:
		err = a.askPassphrase("Current passphrase: ", func(old []byte) error {
			return identity.RemovePassphrase(dir, old)
		})
		if err == nil {
			fmt.Fprintln(a.stderr, unencryptedWarning)
		}
	case form == identity.FormPlain:
		next, err := a.prompt.Confirm("New passphrase: ")
		if err != nil {
			return promptError(err)
		}
		return setupError(identity.SetPassphrase(dir, next))
	default:
		err = a.changePassphrase(dir)
	}
	return setupError(err)
}

// changePassphrase asks for the current and the new passphrase once
// and retries only the current one when it was wrong, so the new
// entry survives across attempts.
func (a *app) changePassphrase(dir string) error {
	var next []byte
	defer func() { clear(next) }()
	return a.askPassphrase("Current passphrase: ", func(old []byte) error {
		if next == nil {
			var err error
			if next, err = a.prompt.Confirm("New passphrase: "); err != nil {
				clear(old)
				return err
			}
		}
		return identity.ChangePassphrase(dir, old, bytes.Clone(next))
	})
}

// askPassphrase prompts and hands the entry to fn, up to
// passphraseAttempts times while fn reports ErrWrongPassphrase. The
// entry is zeroed after each call whether or not fn did so.
func (a *app) askPassphrase(label string, fn func(pass []byte) error) error {
	for attempt := 1; ; attempt++ {
		pass, err := a.prompt(label)
		if err != nil {
			return err
		}
		err = fn(pass)
		clear(pass)
		if !errors.Is(err, identity.ErrWrongPassphrase) || attempt == passphraseAttempts {
			return err
		}
		fmt.Fprintln(a.stderr, "keycell: wrong passphrase, try again")
	}
}

// promptError maps a tty error to exit 1 with the bare message.
func promptError(err error) error {
	return cli.Exit("keycell: "+err.Error(), 1)
}

// setupError maps identity errors to exit 1; prompt errors reach it
// through askPassphrase and are handled the same way.
func setupError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, identity.ErrExists):
		return cli.Exit("keycell: "+identity.ErrExists.Error(), 1)
	case errors.Is(err, identity.ErrWrongPassphrase):
		return cli.Exit("keycell: wrong passphrase", 1)
	}
	return cli.Exit("keycell: "+err.Error(), 1)
}
