package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/internal/tty"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

// secretJSON is the --json shape of get and list: PROTOCOL.md's fields
// without the value, attributes always an object.
type secretJSON struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Attributes map[string]string `json:"attributes"`
	Created    time.Time         `json:"created"`
	Updated    time.Time         `json:"updated"`
}

func toJSON(s keycell.Secret) secretJSON {
	attrs := s.Attributes
	if attrs == nil {
		attrs = map[string]string{}
	}
	return secretJSON{Name: s.Name, Kind: s.Kind, Attributes: attrs, Created: s.Created.UTC(), Updated: s.Updated.UTC()}
}

func (a *app) secretCommands() []*cli.Command {
	kind := &cli.StringFlag{Name: "kind", Aliases: []string{"k"}, Usage: "secret kind"}
	attr := &cli.StringSliceFlag{Name: "attr", Aliases: []string{"a"}, Usage: "attribute `key=value`, repeatable"}
	jsonFlag := &cli.BoolFlag{Name: "json", Usage: "print JSON without the value"}
	return []*cli.Command{
		{
			Name:      "store",
			Usage:     "store a secret, replacing an existing one of the same name",
			ArgsUsage: "<name>",
			Description: "The value is read from stdin, minus one trailing newline. At a terminal it is\n" +
				"prompted for without echo. An existing secret is replaced completely; its\n" +
				"attributes are not carried over.",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "kind", Aliases: []string{"k"}, Usage: "secret kind", Value: "generic"},
				attr,
				&cli.BoolFlag{Name: "no-overwrite", Usage: "fail if the name already exists"},
			},
			// Attribute values may contain commas; the setting is per command.
			DisableSliceFlagSeparator: true,
			Action:                    a.store,
		},
		{
			Name:      "get",
			Usage:     "print a secret's value",
			ArgsUsage: "<name>",
			Description: "The value is written byte for byte; at a terminal a missing trailing newline\n" +
				"is added.",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "attr", Aliases: []string{"a"}, Usage: "print this attribute instead of the value"},
				jsonFlag,
			},
			Action: a.get,
		},
		{
			Name:      "delete",
			Usage:     "delete one or more secrets",
			ArgsUsage: "<name>...",
			Action:    a.delete,
		},
		{
			Name:  "list",
			Usage: "list secret names",
			Flags: []cli.Flag{
				kind,
				&cli.StringFlag{Name: "prefix", Aliases: []string{"p"}, Usage: "names starting with this"},
				attr,
				&cli.BoolFlag{Name: "long", Aliases: []string{"l"}, Usage: "table with kind, update time and attributes"},
				jsonFlag,
			},
			DisableSliceFlagSeparator: true,
			Action:                    a.list,
		},
	}
}

func (a *app) store(ctx context.Context, cmd *cli.Command) error {
	name, err := oneArg(cmd)
	if err != nil {
		return err
	}
	attrs, err := parseAttrs(cmd.StringSlice("attr"))
	if err != nil {
		return err
	}
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	interactive := isTerminal(a.stdin)
	switch {
	case cmd.Bool("no-overwrite"):
		secs, err := c.List(ctx, keycell.Filter{Prefix: name})
		if err != nil {
			return exitError(err)
		}
		for _, s := range secs {
			if s.Name == name {
				return cli.Exit(fmt.Sprintf("keycell: store: %s already exists", name), 1)
			}
		}
	case interactive:
		st, err := c.Status(ctx)
		if err != nil {
			return exitError(err)
		}
		if st.Locked {
			return exitError(keycell.ErrLocked)
		}
	}

	var buf []byte
	if interactive {
		buf, err = a.prompt("Value for " + name + ": ")
		if err != nil {
			return promptError(err)
		}
	} else {
		buf, err = io.ReadAll(a.stdin)
		if err != nil {
			clear(buf)
			return cli.Exit(fmt.Sprintf("keycell: store: read stdin: %v", err), 1)
		}
		buf = bytes.TrimSuffix(buf, []byte("\n"))
	}
	v := keycell.NewValue(buf)
	defer v.Destroy()
	if len(buf) == 0 {
		return cli.Exit("keycell: store: empty value", 1)
	}
	return exitError(c.Store(ctx, keycell.Secret{Name: name, Kind: cmd.String("kind"), Attributes: attrs, Value: v}))
}

func (a *app) get(ctx context.Context, cmd *cli.Command) error {
	name, err := oneArg(cmd)
	if err != nil {
		return err
	}
	if cmd.IsSet("attr") && cmd.Bool("json") {
		return cli.Exit("keycell: get: --attr and --json are mutually exclusive", 2)
	}
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	s, err := c.Get(ctx, name)
	if err != nil {
		return exitError(err)
	}
	defer s.Value.Destroy()
	switch {
	case cmd.IsSet("attr"):
		key := cmd.String("attr")
		val, ok := s.Attributes[key]
		if !ok {
			return cli.Exit(fmt.Sprintf("keycell: get: attribute %q not set", key), 1)
		}
		fmt.Fprintln(a.stdout, val)
	case cmd.Bool("json"):
		return writeJSON(a.stdout, toJSON(*s))
	default:
		b := s.Value.Expose()
		if _, err := a.stdout.Write(b); err != nil {
			return cli.Exit(fmt.Sprintf("keycell: get: write: %v", err), 1)
		}
		if isTerminal(a.stdout) && !bytes.HasSuffix(b, []byte("\n")) {
			fmt.Fprintln(a.stdout)
		}
	}
	return nil
}

// delete tries every name; a missing one is reported and the rest are
// still deleted, any other error stops the run.
func (a *app) delete(ctx context.Context, cmd *cli.Command) error {
	if !cmd.Args().Present() {
		return cli.Exit("keycell: delete needs at least one name", 2)
	}
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	missing := false
	for _, name := range cmd.Args().Slice() {
		switch err := c.Delete(ctx, name); {
		case errors.Is(err, keycell.ErrNotFound):
			fmt.Fprintf(a.stderr, "keycell: delete: not found: %s\n", name)
			missing = true
		case err != nil:
			return exitError(err)
		}
	}
	if missing {
		return cli.Exit("", 1)
	}
	return nil
}

func (a *app) list(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	if cmd.Bool("long") && cmd.Bool("json") {
		return cli.Exit("keycell: list: --long and --json are mutually exclusive", 2)
	}
	attrs, err := parseAttrs(cmd.StringSlice("attr"))
	if err != nil {
		return err
	}
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	secs, err := c.List(ctx, keycell.Filter{Kind: cmd.String("kind"), Prefix: cmd.String("prefix"), Attributes: attrs})
	if err != nil {
		return exitError(err)
	}
	switch {
	case cmd.Bool("json"):
		out := make([]secretJSON, len(secs))
		for i, s := range secs {
			out[i] = toJSON(s)
		}
		return writeJSON(a.stdout, out)
	case cmd.Bool("long"):
		if len(secs) == 0 {
			return nil
		}
		w := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tKIND\tUPDATED\tATTRIBUTES")
		for _, s := range secs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.Kind, s.Updated.Local().Format("2006-01-02 15:04"), formatAttrs(s.Attributes))
		}
		return w.Flush()
	}
	for _, s := range secs {
		fmt.Fprintln(a.stdout, s.Name)
	}
	return nil
}

// parseAttrs splits key=value pairs; a missing '=' or a repeated key is
// a usage error, the daemon validates keys and values.
func parseAttrs(pairs []string) (map[string]string, error) {
	attrs := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, cli.Exit(fmt.Sprintf("keycell: --attr %q: expected key=value", p), 2)
		}
		if _, dup := attrs[k]; dup {
			return nil, cli.Exit(fmt.Sprintf("keycell: --attr %q: key given twice", k), 2)
		}
		attrs[k] = v
	}
	return attrs, nil
}

func formatAttrs(attrs map[string]string) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + attrs[k]
	}
	return strings.Join(parts, ",")
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return cli.Exit(fmt.Sprintf("keycell: %v", err), 1)
	}
	return nil
}

// oneArg returns the single positional argument or a usage error.
func oneArg(cmd *cli.Command) (string, error) {
	if cmd.Args().Len() != 1 {
		return "", cli.Exit(fmt.Sprintf("keycell: %s takes exactly one name", cmd.Name), 2)
	}
	return cmd.Args().First(), nil
}

// isTerminal is true for stdin or stdout when they are a terminal; the
// readers and writers tests inject never are.
func isTerminal(rw any) bool {
	f, ok := rw.(*os.File)
	return ok && tty.IsTerminal(f)
}
