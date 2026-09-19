package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/internal/vault"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

func (a *app) transferCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "export",
			Usage: "write every secret as vault JSON to stdout",
			Description: "The output is the plaintext schema of vault.age, values included, so\n" +
				"'age -d -i id.txt vault.age' and 'keycell export' print the same document.",
			Action: a.export,
		},
		{
			Name:      "import",
			Usage:     "store every secret from a vault JSON file or stdin",
			ArgsUsage: "[file]",
			Description: "Existing names are replaced unless --no-overwrite is given. The first\n" +
				"secret the daemon rejects stops the import; secrets stored before it stay.",
			Flags:  []cli.Flag{&cli.BoolFlag{Name: "no-overwrite", Usage: "skip names that already exist"}},
			Action: a.importCmd,
		},
	}
}

func (a *app) export(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	secs, err := c.List(ctx, keycell.Filter{})
	if err != nil {
		return exitError(err)
	}
	v := vault.New()
	var out []byte
	defer func() { vault.Wipe(v, out) }()
	for _, s := range secs {
		full, err := c.Get(ctx, s.Name)
		if err != nil {
			return exitError(err)
		}
		v.Secrets[s.Name] = &vault.Secret{
			Kind:       full.Kind,
			Value:      full.Value.Expose(),
			Attributes: full.Attributes,
			Created:    full.Created,
			Updated:    full.Updated,
		}
	}
	out, err = vault.Encode(v)
	if err != nil {
		return cli.Exit(fmt.Sprintf("keycell: export: %v", err), 1)
	}
	if _, err := a.stdout.Write(out); err != nil {
		return cli.Exit(fmt.Sprintf("keycell: export: write: %v", err), 1)
	}
	fmt.Fprintln(a.stdout)
	return nil
}

func (a *app) importCmd(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() > 1 {
		return cli.Exit("keycell: import takes at most one file", 2)
	}
	in, err := a.readImport(cmd.Args().First())
	if err != nil {
		return err
	}
	v, err := vault.Decode(in)
	if err != nil {
		clear(in)
		if errors.Is(err, vault.ErrVersion) {
			return cli.Exit(fmt.Sprintf("keycell: import: %v", err), 1)
		}
		return cli.Exit(fmt.Sprintf("keycell: import: invalid document: %v", err), 1)
	}
	defer vault.Wipe(v, in)

	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	skip := map[string]bool{}
	if cmd.Bool("no-overwrite") {
		existing, err := c.List(ctx, keycell.Filter{})
		if err != nil {
			return exitError(err)
		}
		for _, s := range existing {
			skip[s.Name] = true
		}
	}
	names := make([]string, 0, len(v.Secrets))
	for name := range v.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if skip[name] {
			fmt.Fprintf(a.stderr, "keycell: import: skipped, already exists: %s\n", name)
			continue
		}
		s := v.Secrets[name]
		err := c.Store(ctx, keycell.Secret{Name: name, Kind: s.Kind, Attributes: s.Attributes, Value: keycell.NewValue(s.Value)})
		switch {
		case errors.Is(err, keycell.ErrLocked), errors.Is(err, keycell.ErrNotRunning):
			return exitError(err)
		case err != nil:
			return cli.Exit(fmt.Sprintf("keycell: import: %s: %s", name, errorMessage(err)), 1)
		}
	}
	return nil
}

// readImport reads the whole document from the named file, or from stdin
// when no name is given and stdin is not a terminal.
func (a *app) readImport(path string) ([]byte, error) {
	if path == "" {
		if isTerminal(a.stdin) {
			return nil, cli.Exit("keycell: import: no file given and stdin is a terminal", 2)
		}
		b, err := io.ReadAll(a.stdin)
		if err != nil {
			clear(b)
			return nil, cli.Exit(fmt.Sprintf("keycell: import: read stdin: %v", err), 1)
		}
		return b, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, cli.Exit(fmt.Sprintf("keycell: import: %v", err), 1)
	}
	return b, nil
}

// errorMessage is the daemon's message without its code, or the plain
// error text.
func errorMessage(err error) string {
	if e, ok := errors.AsType[*keycell.Error](err); ok {
		return e.Message
	}
	return err.Error()
}
