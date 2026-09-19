package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/pkg/keycell"
)

// envFileName is the mapping file exec reads from the working directory
// when --env-file is not given. It holds names, never values, so it can
// be committed.
const envFileName = "keycell.env"

// envEntry maps one environment variable to the secret whose value it
// receives.
type envEntry struct {
	Var  string
	Name string
}

func (a *app) execCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:      "exec",
			Usage:     "run a command with secrets in its environment",
			ArgsUsage: "-- <cmd> [args...]",
			Description: "Resolves every mapped secret first, then replaces itself with the\n" +
				"command (exec, no parent process). Mappings come from -e and from\n" +
				"keycell.env in the working directory (VAR=name per line, # comments);\n" +
				"-e wins over the file. A missing name aborts before anything starts.",
			Flags: []cli.Flag{
				&cli.StringSliceFlag{Name: "env", Aliases: []string{"e"}, Usage: "`VAR=name`: set VAR to the value of secret name, repeatable"},
				&cli.StringFlag{Name: "env-file", Usage: "mapping `file` (default keycell.env in the working directory, if present)"},
				&cli.BoolFlag{Name: "dry-run", Usage: "print the mapping and check every name, start nothing"},
			},
			Action: a.execCmd,
		},
	}
}

func (a *app) execCmd(ctx context.Context, cmd *cli.Command) error {
	argv := cmd.Args().Slice()
	if len(argv) == 0 {
		return cli.Exit("keycell: exec: missing command", 2)
	}
	mapping, err := a.execMapping(cmd)
	if err != nil {
		return err
	}
	dry := cmd.Bool("dry-run")
	if dry {
		for _, e := range mapping {
			fmt.Fprintf(a.stdout, "%s <- %s\n", e.Var, e.Name)
		}
	}
	secrets, err := a.resolveEnv(ctx, mapping)
	if err != nil {
		return err
	}
	if dry {
		clearEnv(secrets)
		return nil
	}
	return execve(argv, mapping, secrets)
}

// execve replaces the process with argv. The command inherits our
// environment plus the secrets; a secret replaces a variable of the same
// name. Nothing of keycell survives a successful call, so the values go
// away with the process image; on failure they are zeroed.
func execve(argv []string, mapping []envEntry, secrets [][]byte) error {
	defer clearEnv(secrets)
	path, err := exec.LookPath(argv[0])
	if err != nil {
		if e, ok := errors.AsType[*exec.Error](err); ok {
			err = e.Err
		}
		return cli.Exit(fmt.Sprintf("keycell: exec: %s: %v", argv[0], err), 1)
	}
	err = syscall.Exec(path, argv, mergeEnv(os.Environ(), mapping, secrets))
	return cli.Exit(fmt.Sprintf("keycell: exec: %s: %v", argv[0], err), 1)
}

// mergeEnv drops every variable the mapping sets from base and appends
// the secrets. The secret strings alias their byte buffers so that
// clearEnv still zeroes them when Exec fails.
func mergeEnv(base []string, mapping []envEntry, secrets [][]byte) []string {
	drop := make(map[string]bool, len(mapping))
	for _, e := range mapping {
		drop[e.Var] = true
	}
	env := make([]string, 0, len(base)+len(secrets))
	for _, kv := range base {
		if k, _, _ := strings.Cut(kv, "="); !drop[k] {
			env = append(env, kv)
		}
	}
	for _, b := range secrets {
		env = append(env, unsafe.String(unsafe.SliceData(b), len(b)))
	}
	return env
}

// resolveEnv fetches every mapped secret before anything starts and
// returns VAR=value entries in mapping order, as bytes so they can be
// zeroed. Missing names and per-name daemon errors are collected into
// one exit 1; a locked or unreachable daemon stops at the first call.
// An empty mapping needs no daemon.
func (a *app) resolveEnv(ctx context.Context, mapping []envEntry) ([][]byte, error) {
	if len(mapping) == 0 {
		return nil, nil
	}
	c, err := a.connect(ctx)
	if err != nil {
		return nil, exitError(err)
	}
	env := make([][]byte, 0, len(mapping))
	var msgs []string
	for _, e := range mapping {
		s, err := c.Get(ctx, e.Name)
		switch {
		case errors.Is(err, keycell.ErrLocked), errors.Is(err, keycell.ErrNotRunning):
			clearEnv(env)
			return nil, exitError(err)
		case errors.Is(err, keycell.ErrNotFound):
			msgs = append(msgs, "keycell: exec: not found: "+e.Name)
			continue
		case err != nil:
			msgs = append(msgs, fmt.Sprintf("keycell: exec: %s: %s", e.Name, errorMessage(err)))
			continue
		}
		env = append(env, append([]byte(e.Var+"="), s.Value.Expose()...))
		s.Value.Destroy()
	}
	if len(msgs) > 0 {
		clearEnv(env)
		return nil, cli.Exit(strings.Join(msgs, "\n"), 1)
	}
	return env, nil
}

func clearEnv(env [][]byte) {
	for _, b := range env {
		clear(b)
	}
}

// execMapping builds the mapping from the env file and the -e flags.
// Without --env-file, keycell.env is optional; a file named explicitly
// must be readable.
func (a *app) execMapping(cmd *cli.Command) ([]envEntry, error) {
	path, explicit := cmd.String("env-file"), cmd.IsSet("env-file")
	if !explicit {
		path = envFileName
	}
	var file io.Reader
	f, err := os.Open(path)
	switch {
	case err == nil:
		defer f.Close()
		file = f
	case !explicit && errors.Is(err, fs.ErrNotExist):
	default:
		return nil, cli.Exit(fmt.Sprintf("keycell: exec: %v", err), 2)
	}
	return parseEnvMapping(file, path, cmd.StringSlice("env"))
}

// parseEnvMapping reads VAR=name lines from file (nil when there is
// none; source names it in errors) and applies the -e values on top.
// Later entries replace earlier ones with the same variable; the result
// is sorted by variable.
func parseEnvMapping(file io.Reader, source string, flags []string) ([]envEntry, error) {
	byVar := map[string]string{}
	if file != nil {
		sc := bufio.NewScanner(file)
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			e, err := parseEnvEntry(line)
			if err != nil {
				return nil, cli.Exit(fmt.Sprintf("keycell: exec: %s:%d: %v", source, n, err), 2)
			}
			byVar[e.Var] = e.Name
		}
		if err := sc.Err(); err != nil {
			return nil, cli.Exit(fmt.Sprintf("keycell: exec: %s: %v", source, err), 2)
		}
	}
	for _, v := range flags {
		e, err := parseEnvEntry(v)
		if err != nil {
			return nil, cli.Exit(fmt.Sprintf("keycell: exec: -e %q: %v", v, err), 2)
		}
		byVar[e.Var] = e.Name
	}
	entries := make([]envEntry, 0, len(byVar))
	for k, v := range byVar {
		entries = append(entries, envEntry{Var: k, Name: v})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Var < entries[j].Var })
	return entries, nil
}

// parseEnvEntry splits VAR=name and checks both halves; whitespace
// around either is dropped, quotes and expansion are not supported.
func parseEnvEntry(s string) (envEntry, error) {
	k, v, ok := strings.Cut(s, "=")
	if !ok {
		return envEntry{}, errors.New("expected VAR=name")
	}
	k, v = strings.TrimSpace(k), strings.TrimSpace(v)
	switch {
	case k == "":
		return envEntry{}, errors.New("empty variable name")
	case !validEnvVar(k):
		return envEntry{}, fmt.Errorf("invalid variable name %q", k)
	case v == "":
		return envEntry{}, errors.New("empty secret name")
	}
	return envEntry{Var: k, Name: v}, nil
}

// validEnvVar accepts [A-Za-z_][A-Za-z0-9_]*.
func validEnvVar(s string) bool {
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return s != ""
}
