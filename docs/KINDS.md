# Secret kinds

Every secret in the vault has a `kind` and free-form string `attributes` (see [PROTOCOL.md](PROTOCOL.md)). The daemon does not interpret either: it stores them and filters `list` by them, nothing more. What a kind means, which attributes it carries and how an integration picks a secret is a convention between the tool that writes the secret and the tool that reads it. This file collects the conventions keycell's own integrations rely on, so other tools can write secrets keycell understands and read the ones it writes. A tool that needs a new kind invents one; nothing in the daemon or the protocol has to change.

Names are free. The hierarchy with `/` is a convention for `list --prefix`; the names below are what the integrations create on their own, a hand-stored secret can be called anything.

## `git-credential`

Used by `keycell git-credential`, the helper for git's [credential protocol](https://git-scm.com/docs/git-credential). Set it up with

```
git config --global credential.helper '!keycell git-credential'
```

and, to keep separate tokens for repositories on the same host, `git config --global credential.useHttpPath true`, which makes git send the `path` too.

| Field | Where | Meaning |
|---|---|---|
| value | the value | Password or token. It is what git sends as `password=`. |
| `host` | attribute, required | Hostname as git sends it, including a port when the URL has one: `github.com`, `git.example.com:8443`. |
| `protocol` | attribute, optional | `https` or `http`. Unset serves both. |
| `username` | attribute, optional | Sent to git as `username=`, so a URL without a user name still authenticates. Unset serves any user name. |
| `path` | attribute, optional | Repository path without the leading `/`, e.g. `org/repo.git`. Only reaches the helper with `credential.useHttpPath`. |

A secret stored by hand:

```
$ keycell store -k git-credential -a host=github.com -a username=alex github.com/alex
Value for github.com/alex:
```

Secrets the helper creates from `git credential approve` (after a successful prompt through another helper or the terminal) are named `git/<host>` or `git/<host>/<username>` and carry exactly the fields git sent as attributes.

### Matching

For a request the helper lists the `git-credential` secrets whose `host` equals the request's host and compares `protocol`, `username` and `path`:

- A field the request does not send, or the secret does not set, matches anything.
- A field both sides have must be equal.
- Among the matches, the secret with the most set attributes wins.
- Two matches with the same number of attributes are ambiguous: nothing is answered, the names are reported on stderr.

| Secrets | Request | Result |
|---|---|---|
| `git/github.com` {host} | host=github.com, username=carol | `git/github.com`: an unset attribute serves any value |
| `git/github.com/alex` {host, username=alex} | host=github.com | `git/github.com/alex`: git gets `username=alex` |
| `git/github.com/alex` {host, username=alex} | host=github.com, username=bob | no match |
| `git/github.com` {host}, `git/github.com/alex` {host, username} | host=github.com | `git/github.com/alex`: more attributes |
| `git/github.com/alex`, `git/github.com/bob` {host, username each} | host=github.com | ambiguous: put the user in the URL or in `credential.<url>.username` |
| `work` {host, path=org/repo.git}, `git/github.com` {host} | host=github.com, path=org/repo.git | `work` |

`store` (git approve) applies the same rule before writing: a match is updated in place, whatever its name and attributes, which is how a renewed token replaces the old one; only without a match a new `git/<host>[/<username>]` is created. `erase` (git reject) deletes only an unambiguous match.

## `docker-registry`

Used by `docker-credential-keycell`, a [credential helper](https://docs.docker.com/reference/cli/docker/login/#credential-stores) for the docker CLI. It is its own binary; `make install` puts it next to `keycell` and `keycelld` in `~/.local/bin`, and docker finds it on `PATH` by name. Set it up in `~/.docker/config.json`, either as the store for every registry (recommended: the file then holds no credentials at all)

```json
{ "credsStore": "keycell" }
```

or per registry, next to whatever the other registries use:

```json
{ "credHelpers": { "ghcr.io": "keycell" } }
```

| Field | Where | Meaning |
|---|---|---|
| value | the value | Password or token. It is what docker sends as `Secret`. |
| `server` | attribute, required | The server URL exactly as docker sends it. For most registries that is the host, `ghcr.io` or `127.0.0.1:5000`; for Docker Hub it is `https://index.docker.io/v1/`. |
| `username` | attribute, required | Sent to docker as `Username`. |

A secret stored by hand:

```
$ keycell store -k docker-registry -a server=https://index.docker.io/v1/ -a username=alex docker/index.docker.io
Value for docker/index.docker.io:
```

Secrets the helper creates from `docker login` are named `docker/<host>`, the server URL without scheme and path: `docker/index.docker.io`, `docker/ghcr.io`, `docker/127.0.0.1:5000`.

### Matching

Docker asks for a server URL, and the helper lists the `docker-registry` secrets whose `server` equals it. The comparison is literal: no normalization, no scheme or trailing slash added or removed, which is why the Docker Hub secret carries the full `https://index.docker.io/v1/`. One secret is the answer. Two or more are ambiguous: nothing is answered, the names are reported on stderr, and `docker login` for that registry is refused until one of them is deleted or renamed away from the server URL.

| Command | Docker runs it for | Does | stdout | Exit |
|---|---|---|---|---|
| `get` | `docker pull`, `push`, `build`, any registry access | Lists by `server`, fetches the value | `{"ServerURL","Username","Secret"}`; without a match the string `credentials not found in native keychain`, which tells docker to go anonymous | 0; 1 without a match, on ambiguous, locked, not running |
| `store` | `docker login` | Updates the matching secret in place, name and other attributes kept, `username` and value replaced; without a match creates `docker/<host>` | empty | 0; 1 on ambiguous, locked, not running, so a login that cannot save fails visibly |
| `erase` | `docker logout` | Deletes the matching secret; no match is fine | empty | 0; 1 on ambiguous, locked, not running |
| `list` | `docker build`, `docker logout` without a registry | Every `docker-registry` secret with a `server` | `{"<server>":"<username>"}`, `{}` without any | 0; locked also 0 with `{}` and a hint on stderr, so a build does not fail on the listing; 1 not running |

Everything with exit 1 except the missing credentials keeps stdout empty and puts `docker-credential-keycell: <message>` on stderr, which docker shows. The helper never prompts: a locked daemon means `keycell unlock` first, then the docker command again.
