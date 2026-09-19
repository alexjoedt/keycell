# keycell command line

`keycell` is the client of `keycelld`. Every command except `init` and `passphrase` talks to the daemon over the socket described in [PROTOCOL.md](PROTOCOL.md); those two work on the vault directory directly and need no daemon. The CLI is a thin layer over `pkg/keycell`: what it prints is what the library returns, mapped to fixed messages and exit codes so scripts can rely on them.

```
keycell [--config <file>] [--socket <path>] <command> [options] [args]
```

| Global option | Meaning |
|---|---|
| `--config <file>` | Configuration file, default `$XDG_CONFIG_HOME/keycell/config.json`. |
| `--socket <path>` | Daemon socket, default `$XDG_RUNTIME_DIR/keycell/keycell.sock`. Beats `KEYCELL_SOCKET` and the file. |

The data directory comes from the same configuration (`data_dir`, `KEYCELL_DATA_DIR`), the CLI has no flag for it.

## Commands

### `init`

```
keycell init [--no-passphrase]
```

Creates the data directory, a fresh X25519 identity and an empty vault. By default the identity is written to `identity.age`, protected by a passphrase that is prompted for twice at the terminal. `--no-passphrase` writes it unencrypted to `identity.txt` instead, for headless machines; every command that sees this form prints a warning on stderr. A directory that already holds an identity is left alone.

```
$ keycell init --no-passphrase
initialized /home/alex/.local/share/keycell
start the daemon:  systemctl --user enable --now keycell
load the identity: keycell unlock
keycell: warning: identity is stored unencrypted; anyone with read access to identity.txt can decrypt the vault
$ keycell init --no-passphrase
keycell: identity: directory already initialized
```

### `unlock`

```
keycell unlock [--for <duration>]
```

Loads the identity into the daemon. With `identity.age` the passphrase is prompted for at the terminal, three attempts; with `identity.txt` there is no prompt. `--for` overrides the daemon's auto-lock for this session (`30m`, `2h`; `0` disables it until `lock`). An already unlocked daemon is left as it is, the remaining time is reported. Prints the resulting lock state.

```
$ keycell unlock
unlocked, locks in 8h0m
$ keycell unlock
already unlocked, locks in 8h0m
$ keycell unlock --for 1x
keycell: invalid duration "1x" for --for
```

### `lock`

```
keycell lock
```

Drops the identity from the daemon. Silent on success, also when the daemon was locked already. Requests that are in flight finish first.

### `status`

```
keycell status
```

Three lines: the socket path, the identity form on disk (`passphrase-protected`, `UNENCRYPTED`, `none, run 'keycell init'`) and the daemon's lock state. A daemon that is not running is reported on the third line and the command exits 1, so `keycell status` doubles as a health check.

```
$ keycell status
socket:   /run/user/1000/keycell/keycell.sock
identity: UNENCRYPTED
daemon:   unlocked, locks in 8h0m
$ keycell status
socket:   /run/user/1000/keycell/keycell.sock
identity: passphrase-protected
daemon:   not running, run 'systemctl --user start keycell'
```

### `store`

```
keycell store [-k <kind>] [-a <key>=<value>]... [--no-overwrite] <name>
```

Stores a secret. The value comes from stdin or a terminal prompt, see [Value input](#value-input). `--kind`/`-k` defaults to `generic`; `--attr`/`-a` adds one attribute per flag, split at the first `=`, so values may contain `=` and `,`. An existing secret of the same name is replaced completely: kind and attributes are not carried over. `--no-overwrite` refuses instead. Silent on success.

```
$ printf 'ghp_abc123\n' | keycell store github/token -k api-token -a host=github.com
$ printf 'ghp_abc123\n' | keycell store github/token --no-overwrite
keycell: store: github/token already exists
$ keycell store empty </dev/null
keycell: store: empty value
$ keycell store db/prod -a novalue
keycell: --attr "novalue": expected key=value
```

### `get`

```
keycell get [-a <key> | --json] <name>
```

Writes the value byte for byte to stdout: no trailing newline is added unless stdout is a terminal and the value does not end in one, so `$(keycell get name)` and `keycell get name | program` see the exact secret. `--attr`/`-a <key>` prints that attribute plus a newline instead. `--json` prints the record without the value: `name`, `kind`, `attributes` (always an object), `created` and `updated` in RFC 3339 UTC. The two flags exclude each other.

```
$ keycell get github/token
ghp_abc123
$ keycell get -a host github/token
github.com
$ keycell get --json github/token
{
  "name": "github/token",
  "kind": "api-token",
  "attributes": {
    "host": "github.com"
  },
  "created": "2026-09-21T06:17:05.08511078Z",
  "updated": "2026-09-21T06:17:05.08511078Z"
}
$ keycell get -a nope github/token
keycell: get: attribute "nope" not set
```

### `delete`

```
keycell delete <name>...
```

Deletes every named secret. A name that does not exist is reported on stderr and the remaining names are still deleted; the exit code is 1 at the end. Any other error stops the run.

```
$ keycell delete db/prod nope
keycell: delete: not found: nope
```

### `list`

```
keycell list [-k <kind>] [-p <prefix>] [-a <key>=<value>]... [-l | --json]
```

Lists secret names, one per line, in the daemon's order. The filters map to the protocol's `list` parameters: `--kind`/`-k`, `--prefix`/`-p` (names starting with the string; hierarchy with `/` is convention, so `-p github/` selects a subtree) and `--attr`/`-a` (every given attribute must match exactly). `--long`/`-l` prints a table with kind, local update time and attributes; `--json` prints an array of the same objects `get --json` prints. An empty result prints nothing and exits 0, `--json` prints `[]`.

```
$ keycell list
db/prod
github/token
$ keycell list -l
NAME          KIND       UPDATED           ATTRIBUTES
db/prod       generic    2026-09-21 08:17
github/token  api-token  2026-09-21 08:17  host=github.com
$ keycell list -k api-token
github/token
$ keycell list --json -p github/
[
  {
    "name": "github/token",
    "kind": "api-token",
    "attributes": {
      "host": "github.com"
    },
    "created": "2026-09-21T06:17:05.08511078Z",
    "updated": "2026-09-21T06:17:05.08511078Z"
  }
]
```

### `export`

```
keycell export
```

Writes the whole vault as one JSON document to stdout, values included: the same document `age -d -i <identity> vault.age` prints, so a backup made with either tool restores with `import`. Values are base64 as in the protocol. Treat the output like the vault itself.

```
$ keycell export
{"version":1,"secrets":{"github/token":{"kind":"api-token","value":"Z2hwX2FiYzEyMw==","attributes":{"host":"github.com"},"created":"2026-09-21T06:17:05.08511078Z","updated":"2026-09-21T06:17:05.08511078Z"}}}
```

### `import`

```
keycell import [--no-overwrite] [<file>]
```

Reads an `export` document from the file or, without one, from stdin and stores every secret in name order through the daemon, which sets `created` and `updated` afresh. Existing names are replaced unless `--no-overwrite` is given, then they are skipped and named on stderr. A document with a `version` above 1, unknown fields or invalid JSON is rejected before anything is stored. The first secret the daemon rejects stops the import with its name; secrets stored before it stay, there is no rollback. Silent on success.

```
$ keycell export > vault.json
$ keycell import --no-overwrite vault.json
keycell: import: skipped, already exists: github/token
$ printf '{"version":2,"secrets":{}}' | keycell import
keycell: import: vault: unsupported schema version: file has 2, this keycell supports up to 1
```

### `passphrase`

```
keycell passphrase [--remove]
```

Changes the passphrase of `identity.age` (current passphrase, then the new one twice), sets one on `identity.txt` (new passphrase twice, the file becomes `identity.age`) or, with `--remove`, turns `identity.age` back into `identity.txt`. All prompts happen at the terminal. A running daemon is unaffected: it holds the identity, not its protection.

```
$ keycell passphrase --remove
Current passphrase:
keycell: warning: identity is stored unencrypted; anyone with read access to identity.txt can decrypt the vault
$ keycell passphrase --remove
keycell: identity is not passphrase-protected
```

### `exec`

```
keycell exec [-e VAR=name]... [--env-file <file>] [--dry-run] -- <cmd> [args...]
```

Runs a command with secrets in its environment. Each mapping `VAR=name` sets the variable `VAR` to the value of the secret `name`; `-e` is repeatable and the mapping also comes from a file: `--env-file <file>`, or `keycell.env` in the working directory when it exists. The file holds one `VAR=name` per line, blank lines and lines starting with `#` are ignored, whitespace around the variable and the name is dropped; no quotes, no expansion. It contains names only, never values, so it belongs in the repository next to the code that needs it. A `-e` flag beats a file entry with the same variable, a later entry beats an earlier one. Variable names follow `[A-Za-z_][A-Za-z0-9_]*`; a secret of any kind can be mapped, `exec` has no kind of its own.

Every name is resolved before anything starts. A missing name, a locked or stopped daemon and any other daemon error abort with exit 1 and no command run; missing names are all reported, one line each. An empty mapping needs no daemon. `--dry-run` prints `VAR <- name` for every entry, sorted by variable, checks the resolution the same way and starts nothing; values never appear in its output.

After resolution keycell looks the command up on `PATH` and replaces itself with it (`execve`, no fork). There is no keycell process left: the command's exit code is the exit code, signals reach the command directly and the values live only in its environment. The command inherits keycell's full environment plus the secrets; a secret replaces an existing variable of the same name without a warning. What the command does with its environment is beyond keycell's control.

```
$ cat keycell.env
# variables the deploy script expects
GITHUB_TOKEN=github/token
NPM_TOKEN=npm/publish
$ keycell exec --dry-run -- ./deploy.sh
GITHUB_TOKEN <- github/token
NPM_TOKEN <- npm/publish
$ keycell exec -e AWS_SECRET_ACCESS_KEY=aws/deploy -- env | grep -c TOKEN
2
$ keycell exec -e X=svc/missing -- ./deploy.sh
keycell: exec: not found: svc/missing
```

### `git-credential`

```
keycell git-credential <get|store|erase>
```

The helper for git's [credential protocol](https://git-scm.com/docs/gitcredentials): git runs it, the subcommand reads git's `key=value` request from stdin up to the first blank line, and only `protocol`, `host`, `username`, `path` and (for `store` and `erase`) `password` are used; every other line is ignored. The secrets are of kind `git-credential`, the matching rule and the attribute layout are in [KINDS.md](KINDS.md#git-credential). Setup:

```
$ git config --global credential.helper '!keycell git-credential'
$ git config --global credential.useHttpPath true   # optional: path-specific tokens
```

- `get` prints `username=<attribute>` (only when the secret sets it) and `password=<value>`, each with a newline, exit 0. Without a match, or without a `host` in the request, it prints nothing and exits 0, so git goes on to its next helper or its prompt; keycell never gets in the way of hosts it knows nothing about.
- `store` runs after git obtained a credential elsewhere: a matching secret gets the new value and keeps its name and attributes, otherwise `git/<host>` or `git/<host>/<username>` is created with the sent fields as attributes. Without `host` or `password` nothing happens. Exit 0.
- `erase` runs after a credential was rejected and deletes the matching secret. No match is fine. Exit 0.

An ambiguous match (two secrets of equal specificity) answers nothing: `get` reports it and exits 1, `store` and `erase` report it, change nothing and exit 0, since git ignores their outcome anyway. A locked or stopped daemon gives the usual messages with exit 1 on all three; git shows them and falls back to prompting. A value containing a newline cannot be sent to git and fails `get` with exit 1.

```
$ printf 'protocol=https\nhost=github.com\n\n' | keycell git-credential get
username=alex
password=ghp_...
$ printf 'protocol=https\nhost=github.com\n\n' | keycell git-credential get
keycell: git-credential: ambiguous match: git/github.com/alex, git/github.com/bob
```

### `docker-credential-keycell`

```
docker-credential-keycell <get|store|erase|list>
```

The helper docker runs when `~/.docker/config.json` names `"credsStore": "keycell"` or lists it under `credHelpers`. It is a separate binary, since docker looks for `docker-credential-<name>` on `PATH`; `make install` installs it with `keycell` and `keycelld`. It takes no options and reads no config flags: the socket comes from `KEYCELL_SOCKET`, the config file or `$XDG_RUNTIME_DIR` like the CLI's. The secrets are of kind `docker-registry`; setup, naming, the matching rule and the exit codes of each subcommand are in [KINDS.md](KINDS.md#docker-registry). In short: `docker login` and `docker logout` write and delete `docker/<host>`, `docker pull` reads it, and a registry without a secret gets docker's own `credentials not found in native keychain` so docker goes on anonymously. The helper never prompts; a locked daemon answers with `docker-credential-keycell: daemon is locked, run 'keycell unlock'` on stderr, which docker passes through.

```
$ printf 'ghcr.io' | docker-credential-keycell get
{"ServerURL":"ghcr.io","Username":"alex","Secret":"ghp_..."}
$ docker-credential-keycell list
{"ghcr.io":"alex","https://index.docker.io/v1/":"alex"}
```

## Value input

`store` never takes the value as an argument, so it cannot end up in shell history or `ps` output. Where it comes from depends on stdin:

- **stdin is a pipe or file**: it is read to the end, and exactly one trailing `\n` is removed, so `echo secret | keycell store name` stores `secret` and a value that ends in a newline of its own is stored with `printf 'secret\n\n'`. Everything else, including internal newlines and leading or trailing spaces, is kept.
- **stdin is a terminal**: the value is prompted for once without echo (`Value for <name>: `). The daemon's state is checked before the prompt, so a locked or stopped daemon is reported instead of asking for a value that could not be stored.

An empty value is an error either way. `get` mirrors this: the bytes come back unchanged, and the newline is only added for a human at a terminal.

Every secret has a kind; `store` defaults it to `generic`. Kinds and attributes are free-form for the CLI, the conventions integrations rely on are listed in [KINDS.md](KINDS.md). Storing under an existing name replaces the whole record: to change one attribute, store the value again with the full set of attributes.

## Exit codes and messages

| Exit | Meaning |
|---|---|
| 0 | Success. Also `unlock` on an unlocked daemon and `list` with no match. |
| 1 | The daemon or the vault said no: locked, not running, not found, invalid record, wrong or missing passphrase, failed prompt. Also `git-credential get` on an ambiguous match or a malformed request, and `exec` with a missing name or a command that is not found or not executable. |
| 2 | Usage error: unknown command or flag, wrong number of arguments, malformed `--attr` or `--for`, `--attr` with `--json`, `-l` with `--json`, unknown `git-credential` subcommand, `exec` without a command, with a malformed mapping line or with an unreadable `--env-file`. |

Every message goes to stderr and starts with `keycell:`. The fixed ones scripts can match:

| Message | When |
|---|---|
| `keycell: daemon is locked, run 'keycell unlock'` | Any secret command while the daemon holds no identity. |
| `keycell: daemon is not running, run 'systemctl --user start keycell'` | The socket does not answer. `status` prints the hint on stdout instead. |
| `keycell: no TTY for passphrase prompt` | `unlock` with `identity.age`, `init` or `passphrase` without a controlling terminal (systemd, cron, `ssh` without `-t`). Passphrases are never read from the environment or stdin. |
| `keycell: wrong passphrase` | Three wrong attempts. |
| `keycell: store: empty value` | Nothing on stdin, or an empty prompt answer. |
| `keycell: store: <name> already exists` | `--no-overwrite` hit an existing name. |
| `keycell: no identity, run 'keycell init'` | `unlock` or `passphrase` before `init`. |
| `keycell: delete: not found: <name>` | Per missing name; the command still exits 1 at the end. |
| `keycell: import: skipped, already exists: <name>` | Per skipped name with `--no-overwrite`; exit stays 0. |
| `keycell: git-credential: ambiguous match: <name>, <name>` | `get`, exit 1. `store` and `erase` append `, nothing stored` or `, nothing erased` and exit 0. |
| `keycell: git-credential: value of <name> contains a newline` | `get` found a secret git's line protocol cannot carry. |
| `keycell: exec: not found: <name>` | Per missing name of the mapping; nothing is started, exit 1. |
| `keycell: exec: <name>: <message>` | The daemon rejected a name for another reason, per name, exit 1. |
| `keycell: exec: missing command` | `exec` without a command after `--`, exit 2. |
| `keycell: exec: <file>:<line>: <reason>`, `keycell: exec: -e "<value>": <reason>` | A malformed mapping entry: `expected VAR=name`, `empty variable name`, `empty secret name`, `invalid variable name "<var>"`. Exit 2. |
| `keycell: exec: <cmd>: <error>` | The command was not found on `PATH`, is not executable or `execve` failed, exit 1. |
| `keycell: warning: identity is stored unencrypted; ...` | After any command that leaves `identity.txt` behind. Not an error. |

Errors the daemon reports (`INVALID_ARGUMENT`, `NOT_FOUND`, `INTERNAL`, see [PROTOCOL.md](PROTOCOL.md#error-codes)) are printed as `keycell: <message>` with exit 1.

## Hardening

The CLI makes itself non-dumpable (`PR_SET_DUMPABLE=0`, soft `RLIMIT_CORE` 0) before doing anything else, so a crash leaves no core file and a debugger of the same user cannot attach, and it zeroes value and passphrase buffers after use. Setting `KEYCELL_DEBUG_DUMPABLE=1` skips this for debugging; the CLI then prints `keycell: warning:` and continues.
