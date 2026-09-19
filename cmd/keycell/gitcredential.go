package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/alexjoedt/keycell/pkg/keycell"
)

const gitKind = "git-credential"

func (a *app) gitCredentialCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "git-credential",
			Usage: "git credential helper: get, store and erase",
			Description: "Configure git with `credential.helper = !keycell git-credential`. Each\n" +
				"subcommand reads git's key=value request from stdin; the matching rules\n" +
				"are in docs/KINDS.md.",
			Action: a.gitCredentialRoot,
			Commands: []*cli.Command{
				{
					Name:   "get",
					Usage:  "print username and password for the request, nothing without a match",
					Action: a.gitCredentialGet,
				},
				{
					Name:   "store",
					Usage:  "save the password into the matching secret, or a new git/<host>[/<user>]",
					Action: a.gitCredentialStore,
				},
				{
					Name:   "erase",
					Usage:  "delete the matching secret",
					Action: a.gitCredentialErase,
				},
			},
		},
	}
}

func (a *app) gitCredentialRoot(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Present() {
		return cli.Exit(fmt.Sprintf("keycell: git-credential: unknown subcommand %q", cmd.Args().First()), 2)
	}
	return cli.ShowSubcommandHelp(cmd)
}

// gitCredentialGet answers git's get: a match prints username (when the
// secret sets it) and password; no match or no host prints nothing so
// git moves on to the next helper or its prompt.
func (a *app) gitCredentialGet(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	req, err := a.gitRequest()
	if err != nil {
		return err
	}
	defer clear(req.password)
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	s, err := gitMatch(ctx, c, req)
	if errors.Is(err, errNoMatch) {
		return nil
	}
	if err != nil {
		return gitError(err)
	}
	full, err := c.Get(ctx, s.Name)
	if err != nil {
		return exitError(err)
	}
	defer full.Value.Destroy()
	b := full.Value.Expose()
	if bytes.ContainsRune(b, '\n') {
		return gitExitf("value of %s contains a newline", s.Name)
	}
	if u, ok := s.Attributes["username"]; ok {
		fmt.Fprintf(a.stdout, "username=%s\n", u)
	}
	// The value is written as bytes, never through fmt.
	for _, part := range [][]byte{[]byte("password="), b, []byte("\n")} {
		if _, err := a.stdout.Write(part); err != nil {
			return gitExitf("write: %v", err)
		}
	}
	return nil
}

// gitRequest parses stdin; a request without host is answered with
// nothing, which is a nil error and no output for every subcommand.
func (a *app) gitRequest() (gitRequest, error) {
	req, err := parseGitRequest(a.stdin)
	if errors.Is(err, errNoHost) {
		return req, errGitDone
	}
	if err != nil {
		return req, gitExitf("%v", err)
	}
	return req, nil
}

// gitCredentialStore upserts git's approved credential: the matching
// secret keeps its name and attributes and gets the new value; without
// a match a new git/<host>[/<username>] is created. Ambiguous stores
// nothing and says so; git ignores the outcome either way.
func (a *app) gitCredentialStore(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	req, err := a.gitRequest()
	if err != nil {
		return err
	}
	v := keycell.NewValue(req.password)
	defer v.Destroy()
	if len(req.password) == 0 {
		return nil
	}
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	s, err := gitMatch(ctx, c, req)
	switch {
	case errors.Is(err, errNoMatch):
		s = &keycell.Secret{Name: gitName(req), Kind: gitKind, Attributes: gitAttrs(req)}
	case err != nil:
		return a.gitAmbiguous(err, "nothing stored")
	}
	s.Value = v
	return exitError(c.Store(ctx, *s))
}

// gitCredentialErase deletes the one secret git's rejected credential
// matches; no match is fine, ambiguous deletes nothing.
func (a *app) gitCredentialErase(ctx context.Context, cmd *cli.Command) error {
	if err := noArgs(cmd); err != nil {
		return err
	}
	req, err := a.gitRequest()
	if err != nil {
		return err
	}
	clear(req.password)
	c, err := a.connect(ctx)
	if err != nil {
		return exitError(err)
	}
	s, err := gitMatch(ctx, c, req)
	switch {
	case errors.Is(err, errNoMatch):
		return nil
	case err != nil:
		return a.gitAmbiguous(err, "nothing erased")
	}
	if err := c.Delete(ctx, s.Name); err != nil && !errors.Is(err, keycell.ErrNotFound) {
		return exitError(err)
	}
	return nil
}

// gitAmbiguous reports an ambiguous match on stderr with exit 0, so a
// store or erase that cannot pick a secret does not fail git's command;
// any other error is the daemon's.
func (a *app) gitAmbiguous(err error, outcome string) error {
	if _, ok := errors.AsType[*ambiguousError](err); ok {
		fmt.Fprintf(a.stderr, "keycell: git-credential: %v, %s\n", err, outcome)
		return nil
	}
	return exitError(err)
}

func gitName(req gitRequest) string {
	if req.username != "" {
		return "git/" + req.host + "/" + req.username
	}
	return "git/" + req.host
}

// gitAttrs keeps exactly the fields git sent, so an absent field keeps
// matching everything later.
func gitAttrs(req gitRequest) map[string]string {
	attrs := map[string]string{"host": req.host}
	for k, v := range map[string]string{"protocol": req.protocol, "username": req.username, "path": req.path} {
		if v != "" {
			attrs[k] = v
		}
	}
	return attrs
}

// gitMatch lists the host's git-credential secrets and picks one per
// matchGitCredential. Daemon errors come back unwrapped for exitError.
func gitMatch(ctx context.Context, c *keycell.Client, req gitRequest) (*keycell.Secret, error) {
	secs, err := c.List(ctx, keycell.Filter{Kind: gitKind, Attributes: map[string]string{"host": req.host}})
	if err != nil {
		return nil, err
	}
	return matchGitCredential(secs, req)
}

// gitError maps a match error: ambiguous is the helper's own message,
// everything else comes from the daemon and goes through exitError.
func gitError(err error) error {
	if _, ok := errors.AsType[*ambiguousError](err); ok {
		return gitExitf("%v", err)
	}
	return exitError(err)
}

func gitExitf(format string, args ...any) error {
	return cli.Exit("keycell: git-credential: "+fmt.Sprintf(format, args...), 1)
}

// gitRequest holds the fields of a git credential request that keycell
// matches on, plus the password git sends with store and erase; every
// other line is skipped.
type gitRequest struct {
	protocol string
	host     string
	username string
	path     string
	password []byte
}

var (
	errNoHost  = errors.New("host missing")
	errNoMatch = errors.New("no match")
)

// errGitDone ends a subcommand early with exit 0 and no output.
var errGitDone = cli.Exit("", 0)

// parseGitRequest reads key=value lines up to the first blank line or
// EOF. Unknown keys are ignored; a line without '=' is an error, a
// request without host is errNoHost.
func parseGitRequest(r io.Reader) (gitRequest, error) {
	var req gitRequest
	// The scanner's own buffer sees the password line; it is wiped on
	// return, a longer line would grow into an unwiped copy.
	buf := make([]byte, 4096)
	defer clear(buf)
	sc := bufio.NewScanner(r)
	sc.Buffer(buf, 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		if len(line) == 0 {
			break
		}
		key, val, ok := bytes.Cut(line, []byte("="))
		if !ok {
			return req, fmt.Errorf("line %d: no '=' in %q", n, line)
		}
		switch string(key) {
		case "protocol":
			req.protocol = string(val)
		case "host":
			req.host = string(val)
		case "username":
			req.username = string(val)
		case "path":
			req.path = string(val)
		case "password":
			clear(req.password)
			req.password = bytes.Clone(val)
		}
	}
	if err := sc.Err(); err != nil {
		return req, err
	}
	if req.host == "" {
		return req, errNoHost
	}
	return req, nil
}

// ambiguousError names the equally specific secrets a request matched.
type ambiguousError struct {
	names []string
}

func (e *ambiguousError) Error() string {
	return "ambiguous match: " + strings.Join(e.names, ", ")
}

// matchGitCredential picks the secret for req among cands: kind
// git-credential, same host, and protocol, username and path equal
// wherever both the secret and the request set them (git sends no
// username for a plain https URL, and a secret without one serves any).
// The candidate with the most set attributes wins; errNoMatch without
// one, ambiguousError on a tie.
func matchGitCredential(cands []keycell.Secret, req gitRequest) (*keycell.Secret, error) {
	var best []keycell.Secret
	bestScore := -1
	for _, s := range cands {
		score, ok := gitScore(s, req)
		if !ok {
			continue
		}
		switch {
		case score > bestScore:
			best, bestScore = []keycell.Secret{s}, score
		case score == bestScore:
			best = append(best, s)
		}
	}
	switch len(best) {
	case 0:
		return nil, errNoMatch
	case 1:
		return &best[0], nil
	}
	names := make([]string, len(best))
	for i, s := range best {
		names[i] = s.Name
	}
	sort.Strings(names)
	return nil, &ambiguousError{names: names}
}

// gitScore reports whether s matches req and how many optional
// attributes it pins down.
func gitScore(s keycell.Secret, req gitRequest) (int, bool) {
	if s.Kind != gitKind || s.Attributes["host"] != req.host {
		return 0, false
	}
	score := 0
	for _, f := range [...]struct{ attr, want string }{
		{"protocol", req.protocol},
		{"username", req.username},
		{"path", req.path},
	} {
		v, ok := s.Attributes[f.attr]
		if !ok {
			continue
		}
		if f.want != "" && v != f.want {
			return 0, false
		}
		score++
	}
	return score, true
}
