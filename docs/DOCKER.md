# Using keycell with docker

A walkthrough for keeping registry logins in the vault instead of `~/.docker/config.json`. The helper's subcommands and exit codes are in [CLI.md](CLI.md#docker-credential-keycell), the attribute layout and matching rule in [KINDS.md](KINDS.md#docker-registry); this guide shows the setup and what to expect day to day.

## Setup

Docker finds a credential helper by name: for `keycell` it runs `docker-credential-keycell` from `PATH`. `make install` puts the binary into `~/.local/bin` next to `keycell` and `keycelld`; check that docker can see it:

```
$ docker-credential-keycell list
{}
```

Then point docker at it in `~/.docker/config.json`. For every registry:

```json
{ "credsStore": "keycell" }
```

or only for some, next to whatever the others use:

```json
{ "credHelpers": { "ghcr.io": "keycell", "registry.example.com": "keycell" } }
```

Docker reads the file on every command; no restart. `docker` here means the CLI: podman, buildah and other clients that read the same config and speak the same helper protocol work identically.

## First login

`docker login` prompts as usual and hands the answer to the helper, which stores it as `docker/<host>`:

```
$ docker login ghcr.io
Username: alex
Password:
Login Succeeded
$ keycell list -l -k docker-registry
NAME            KIND             UPDATED           ATTRIBUTES
docker/ghcr.io  docker-registry  2026-09-21 09:20  server=ghcr.io,username=alex
$ docker pull ghcr.io/org/image:latest
```

`config.json` now holds the registry under `auths` with an empty entry, which is how docker remembers that a helper has the credential, and no token. Docker Hub is special: `docker login` without a registry stores `docker/index.docker.io` with `server=https://index.docker.io/v1/`, the URL docker uses for Hub internally.

A token you already hold goes in directly:

```
$ keycell store -k docker-registry -a server=ghcr.io -a username=alex docker/ghcr.io
Value for docker/ghcr.io:
```

`server` must be exactly what docker asks for: the host with a port when there is one (`127.0.0.1:5000`), no scheme, except for Hub where it is the full `https://index.docker.io/v1/`. The name is free.

Non-interactive logins work the same way, the value just travels through stdin:

```
$ printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u alex --password-stdin
```

## Renewed tokens and logout

`docker login` again with the same registry replaces the value and user name of the existing secret; its name is kept. `docker logout ghcr.io` deletes it. A `keycell delete docker/ghcr.io` has the same effect as logout, except that docker keeps the empty `auths` entry, which is harmless.

## Registries without a login

A registry with no secret gets `credentials not found in native keychain` from the helper, which is docker's own phrase for "go anonymous". Public pulls therefore work with `credsStore` set for everything; only a private registry that has never been logged into fails, with docker's normal `unauthorized` error.

## When the daemon is locked

The helper never prompts. A locked daemon makes `docker pull`, `push` and `login` fail with the message on stderr:

```
$ docker pull ghcr.io/org/private:latest
error getting credentials - err: exit status 1, out: `docker-credential-keycell: daemon is locked, run 'keycell unlock'`
```

`keycell unlock`, then the command again. `docker build` is the exception: the listing it asks for at start answers `{}` when locked, so a build of public images does not break; a `FROM` on a private registry then fails at pull time like above. On a headless machine the unit's `ExecStartPost` drop-in from [contrib/keycell.service](../contrib/keycell.service) unlocks at boot.

## Compose and build secrets

Docker's own credential flow covers image pulls and pushes. Secrets a container or a build needs are a different matter; `keycell exec` supplies them as environment variables without writing an `.env` file:

```
$ cat keycell.env
DATABASE_URL=app/db-url
API_KEY=app/api-key
$ keycell exec -- docker compose up
```

Compose reads `DATABASE_URL` and `API_KEY` from its environment for `${VAR}` substitution. For a build secret the same works with `--secret id=key,env=API_KEY`:

```
$ keycell exec -e API_KEY=app/api-key -- docker build --secret id=api,env=API_KEY .
```

Any kind can be mapped, `exec` does not care that a `docker-registry` secret is meant for docker; `-e TOKEN=docker/ghcr.io` gives a script the registry token.

## Root and rootless daemons

Credentials are the CLI's business, not the daemon's, so the setup is per user: the one running `docker` needs the helper on `PATH` and a keycell session. `sudo docker` runs as root with root's `~/.docker/config.json` and no user session of yours; either add yourself to the `docker` group, or go rootless. Rootless docker and podman run entirely under your user and need nothing extra.

The same holds for CI runners and containers that run `docker`: they need their own `keycelld`, socket and unlocked identity, or a plain `docker login` from a variable instead of the helper.

## Migrating from `config.json`

Without a helper, `docker login` writes `auths.<server>.auth` as base64 `user:password` into `config.json`. Move each into the vault, then log in again or remove the entries:

```
$ jq -r '.auths | to_entries[] | select(.value.auth) | "\(.key) \(.value.auth)"' ~/.docker/config.json
ghcr.io Z2hj...
$ printf 'Z2hj...' | base64 -d
alex:ghp_...
$ printf '%s' 'ghp_...' | keycell store -k docker-registry -a server=ghcr.io -a username=alex docker/ghcr.io
```

Then set `credsStore` and delete the `auth` fields, or simply run `docker logout <server>` before switching and `docker login` after. Hub's key in `auths` is `https://index.docker.io/v1/`; keep it as `server` unchanged.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `error getting credentials - err: exec: "docker-credential-keycell": executable file not found in $PATH` | `~/.local/bin` is not on the `PATH` of the shell or service running docker. |
| `docker-credential-keycell: ambiguous match: docker/ghcr.io, work/ghcr.io` | Two `docker-registry` secrets carry the same `server`. Delete or rename one; `docker login` for that registry refuses until then. |
| `docker login` succeeds, `docker pull` still `unauthorized` | Hub: the secret's `server` is `index.docker.io` or `docker.io` instead of `https://index.docker.io/v1/`. Compare `keycell list -l -k docker-registry` with `docker-credential-keycell list`. |
| `docker logout` says not logged in | There was no secret; harmless. |
| Works in the terminal, not from a service or IDE | That process has no `XDG_RUNTIME_DIR` or a different one; set `KEYCELL_SOCKET` to the socket path shown by `keycell status`. |

`printf 'ghcr.io' | docker-credential-keycell get` shows exactly what docker gets for a server, without pulling anything.
