# keycell

Developer credentials tend to end up in plain text on disk: tokens in `~/.gitconfig` and `~/.docker/config.json`, API keys in `.env` files and shell profiles, readable by every process, backup and dotfile sync. keycell keeps them in one [age](https://age-encryption.org)-encrypted vault instead. A small daemon, `keycelld`, is unlocked once with your passphrase and hands secrets to git, docker and any program you start with `keycell exec`; nothing secret is written to disk in the clear, and a backup of the vault directory is a complete backup. It is Linux-only, built for one user on their own machine, and it deliberately has no per-client access control: every process of your UID can read secrets while the daemon is unlocked (see [Threat model](#threat-model)).

## Installation

Requirements: Linux with a systemd user session, Go 1.27 or newer to build. The `age` CLI is optional, for reading the vault without keycell.

```
$ git clone https://github.com/alexjoedt/keycell && cd keycell
$ make install
$ make install-service
```

`make install` builds and installs three binaries into `~/.local/bin`: `keycell` (the CLI), `keycelld` (the daemon) and `docker-credential-keycell` (the docker helper). Make sure that directory is on your `PATH`; docker finds its helper by name. `make install-service` copies the systemd user unit from [`contrib/keycell.service`](contrib/keycell.service) to `~/.config/systemd/user/` and reloads systemd. Both take `BINDIR=` and `UNITDIR=` for other locations; the unit's `ExecStart` expects `keycelld` in `~/.local/bin`, so edit it when `BINDIR` differs. Without make, `go install ./cmd/...` puts the binaries into `$GOBIN` (default `~/go/bin`) and the unit is copied by hand.

Then start the daemon:

```
$ systemctl --user enable --now keycell
$ keycell status
socket:   /run/user/1000/keycell/keycell.sock
identity: none, run 'keycell init'
daemon:   locked
```

## First steps

Create the identity and an empty vault, then load the identity into the daemon:

```
$ keycell init
New passphrase:
Repeat passphrase:
initialized /home/alex/.local/share/keycell
start the daemon:  systemctl --user enable --now keycell
load the identity: keycell unlock
$ keycell unlock
Passphrase:
unlocked, locks in 8h0m
```

The daemon now answers requests until `keycell lock`, the auto-lock (8 hours by default) or a restart. Store and read a secret:

```
$ keycell store github/token
Value for github/token:
$ keycell get github/token
ghp_...
$ keycell list
github/token
```

### git

Register keycell as git's credential helper. The first `git push` against an HTTPS remote prompts for the token as usual; git hands it to keycell, which stores it as `git/<host>`, and every later push reads it from the vault. `~/.gitconfig` never sees the token.

```
$ git config --global credential.helper '!keycell git-credential'
$ git push
Username for 'https://github.com': alex
Password for 'https://alex@github.com':
```

### docker

Point docker's credential store at keycell in `~/.docker/config.json`; `docker login` then stores into the vault and `docker pull` reads from it.

```json
{ "credsStore": "keycell" }
```

### Environment variables for a program

Put a `keycell.env` next to your project; it maps variables to secret names and holds no values, so it can be committed. `keycell exec` resolves every name first, then replaces itself with the command.

```
$ cat keycell.env
GITHUB_TOKEN=github/token
$ keycell exec -- ./deploy.sh
$ keycell exec --dry-run -e NPM_TOKEN=npm/publish -- ./deploy.sh
GITHUB_TOKEN <- github/token
NPM_TOKEN <- npm/publish
```

## Using keycell from your own code

Go programs import `pkg/keycell` ([reference](https://pkg.go.dev/github.com/alexjoedt/keycell/pkg/keycell)); the common case is three lines and needs no age import:

```go
s, err := client.Get(ctx, "github/token")
defer s.Value.Destroy()
use(s.Value.Expose())
```

Other languages talk NDJSON over the Unix socket; the methods, error codes and a `nc` walkthrough are in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Threat model

keycell protects secrets at rest. The vault is a single `vault.age`, encrypted to an X25519 identity; the identity lives in `identity.age`, encrypted with your passphrase (age's scrypt recipient). Both files together are useless without the passphrase, so they can sit in a backup, a synced directory or on a lost laptop. No plaintext secret is ever written to disk by keycell.

It does not protect a running, unlocked daemon from your own user. Anything that runs as your UID can connect to the socket and call `get`; anything that can `ptrace` the daemon or read `/proc/<pid>/mem`, and of course root, can take the identity from memory and decrypt the vault. A compromised machine is out of scope. In that respect keycell is like ssh-agent or a desktop keyring: the boundary is the user, not the process. What it does within that boundary:

- The socket accepts connections only from the same UID (`SO_PEERCRED`).
- The daemon holds only the identity in memory, in an `mlock`ed page that is excluded from core dumps; each request decrypts the vault, takes what it needs and zeroes the plaintext before answering.
- Daemon and CLI set `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`, so there are no core files and a same-user debugger cannot attach after startup. Values and passphrases are held in byte buffers that are zeroed after use.
- `keycell lock`, the auto-lock, SIGTERM and a restart drop the identity; a locked daemon cannot decrypt anything.

Memory hygiene is best effort: Go's runtime and the kernel can still leave copies (swap without encryption, hibernation images). Encrypt your swap.

## Operation

### Auto-lock

The daemon locks itself 8 hours after `unlock`, an absolute limit that activity does not extend. `keycell unlock --for 2h` sets a different limit for this session, `--for 0` disables it until `keycell lock`. The default comes from `auto_lock` in the config file or `KEYCELL_AUTO_LOCK` (`30m`, `12h`, `0`). `keycell status` shows the remaining time.

### Screen lock and suspend

keycell does not talk to logind; bind `keycell lock` to whatever locks your screen. Examples, not automation:

```
# sway: lock the vault whenever the screen locks, and before suspend
exec swayidle -w \
    timeout 600 'keycell lock; swaylock -f' \
    before-sleep 'keycell lock; swaylock -f'

# X11: xss-lock runs the locker on screensaver and suspend events
xss-lock -- sh -c 'keycell lock; i3lock -n' &
```

A system-wide hook covers every user before suspend and hibernation. It runs as root, so it has to reach each user's socket and binary explicitly:

```sh
#!/bin/sh
# /usr/lib/systemd/system-sleep/keycell-lock
[ "$1" = pre ] || exit 0
for dir in /run/user/*; do
    sock="$dir/keycell/keycell.sock"
    [ -S "$sock" ] || continue
    user=$(id -nu "${dir#/run/user/}")
    runuser -u "$user" -- "$(getent passwd "$user" | cut -d: -f6)/.local/bin/keycell" --socket "$sock" lock
done
```

### Headless machines

A server or a cron host has no terminal to type a passphrase into, and keycell never reads one from the environment or stdin: a passphrase that a process can read is no protection, only an extra file to leak. Choose explicitly: `keycell init --no-passphrase` stores the identity in the clear as `identity.txt`, and every command that sees that form warns about it:

```
keycell: warning: identity is stored unencrypted; anyone with read access to identity.txt can decrypt the vault
```

`keycell unlock` then needs no prompt, and a drop-in lets the unit unlock right after the socket is up. The daemon reports `READY=1` only once it listens, so the order is guaranteed:

```ini
# ~/.config/systemd/user/keycell.service.d/unlock.conf
[Service]
ExecStartPost=%h/.local/bin/keycell unlock
```

`keycell passphrase` turns `identity.txt` back into a passphrase-protected `identity.age` at any time; `keycell passphrase --remove` goes the other way.

### Backup and restore

The data directory (`~/.local/share/keycell` by default, `data_dir` in the config) is the complete state: `vault.age`, `identity.age` or `identity.txt`, and `vault.age.bak`, the previous vault kept by every write. Back it up like any other directory:

```
$ restic backup ~/.local/share/keycell
```

To restore, put the directory back on the new machine, start the daemon and run `keycell unlock`; there is no migration step. Without keycell at all, the `age` CLI and `jq` read the vault:

```
$ age -d identity.age > id.txt
$ age -d -i id.txt vault.age | jq .
```

### Configuration

Four values, each resolved as flag > environment > config file > default:

| Value | File key | Environment | Default |
|---|---|---|---|
| Config file | | `KEYCELL_CONFIG`, `--config` | `$XDG_CONFIG_HOME/keycell/config.json` |
| Data directory | `data_dir` | `KEYCELL_DATA_DIR` | `$XDG_DATA_HOME/keycell` |
| Socket | `socket` | `KEYCELL_SOCKET`, `--socket` | `$XDG_RUNTIME_DIR/keycell/keycell.sock` |
| Auto-lock | `auto_lock` | `KEYCELL_AUTO_LOCK` | `8h` |
| Log level | `log_level` | `KEYCELL_LOG_LEVEL` | `info` |

The daemon and every client read the same file, so a custom socket path set there is seen by all of them. Details in [docs/CLI.md](docs/CLI.md).

## Documentation

- [docs/CLI.md](docs/CLI.md): every `keycell` command with options, output, exit codes and the fixed messages scripts can match.
- [docs/PROTOCOL.md](docs/PROTOCOL.md): the wire protocol between clients and `keycelld`.
- [docs/KINDS.md](docs/KINDS.md): the secret kinds git and docker use, their attributes and matching rules.
- [docs/GIT.md](docs/GIT.md): guide for git, from the first push to two accounts on one host, per-repository tokens and migration.
- [docs/DOCKER.md](docs/DOCKER.md): guide for docker, from the first login to compose secrets, root vs. rootless and migration.
- [contrib/keycell.service](contrib/keycell.service): the systemd user unit, with the headless drop-in in its header.

## License

[MIT](LICENSE).
