# Using keycell with git

A walkthrough for keeping git's HTTPS tokens in the vault. The reference for the helper is in [CLI.md](CLI.md#git-credential), the attribute layout and matching rule in [KINDS.md](KINDS.md#git-credential); this guide only shows how to set it up and what to expect day to day. SSH remotes are not affected: git never asks a credential helper for them.

## Setup

Register the helper once. The `!` tells git to run the string as a shell command instead of looking for a `git-credential-keycell` binary, and the subcommand git appends (`get`, `store`, `erase`) lands after `git-credential`:

```
$ git config --global credential.helper '!keycell git-credential'
```

That is all. With the daemon running and unlocked, the next `git push` or `git fetch` against an HTTPS remote goes through keycell.

## First push

Nothing has to be stored by hand. The first push against a host keycell does not know prompts as usual; git hands the answer to the helper, which stores it, and every later request is answered from the vault:

```
$ git push
Username for 'https://github.com': alex
Password for 'https://alex@github.com':
$ keycell list -l -k git-credential
NAME                 KIND            UPDATED           ATTRIBUTES
git/github.com/alex  git-credential  2026-09-21 09:12  host=github.com,protocol=https,username=alex
$ git push
Everything up-to-date
```

The secret is named `git/<host>/<username>` (or `git/<host>` when the URL carried no user name and git asked for none). `~/.gitconfig` and `~/.git-credentials` never see the token.

If you already hold a token, store it directly instead of waiting for the prompt:

```
$ keycell store -k git-credential -a host=github.com -a username=alex git/github.com/alex
Value for git/github.com/alex:
```

`host` is what git sends: the host name plus the port when the URL has one, `git.example.com:8443`. `username` is optional; without it git still gets a password for any user name on that host, and with it git also gets `username=alex` back, so a plain `https://github.com/org/repo` remote works without a user in the URL.

## Renewed and revoked tokens

When a token expires, git reports the rejection and asks the helper to `erase`; the next push prompts again and the new answer replaces the old secret in place. To swap a token ahead of time, store it under the existing name: the value is replaced and the attributes kept.

```
$ printf '%s\n' "$NEW_TOKEN" | keycell store -k git-credential -a host=github.com -a username=alex git/github.com/alex
```

`store` replaces the whole record, so repeat the kind and the attributes. To drop a host entirely, delete the secret:

```
$ keycell delete git/github.com/alex
```

## Two accounts on one host

Two secrets for the same host with different `username` are both valid; git just has to say which one it wants. A request without a user name matches both and the helper refuses to guess:

```
$ git fetch
keycell: git-credential: ambiguous match: git/github.com/alex, git/github.com/work
Username for 'https://github.com':
```

Put the user in the remote URL (`https://work@github.com/org/repo`) or let git add it for a URL prefix:

```
$ git config --global credential.https://github.com/org.username work
```

With the user name in the request only one secret matches.

## A token per repository

Fine-grained tokens are scoped to a repository, so one per host is not enough. Ask git to send the repository path along and store the token with a `path` attribute:

```
$ git config --global credential.useHttpPath true
$ keycell store -k git-credential -a host=github.com -a path=org/repo.git -a username=alex github/org-repo
Value for github/org-repo:
```

The path is the remote URL after the host, without the leading `/`, exactly as git sends it (`org/repo.git`, or `org/repo` when the remote is written without the suffix). A secret with a `path` beats one without for that repository, and requests for other repositories still fall through to `git/github.com/alex`. The name is free: `github/org-repo` is as good as any.

## When the daemon is locked

The helper never prompts for the passphrase. A locked or stopped daemon makes it fail, git prints the message and falls back to its own prompt:

```
$ git push
keycell: daemon is locked, run 'keycell unlock'
Username for 'https://github.com':
```

Press Ctrl-C, run `keycell unlock`, push again. A pasted token at that prompt would be sent to the host but not stored, since `store` fails the same way. On a headless machine the unit's `ExecStartPost` drop-in from [contrib/keycell.service](../contrib/keycell.service) unlocks at boot.

## Scripts and CI

For a script that needs the token as a variable rather than through git, `keycell exec` sets it from the same secret:

```
$ keycell exec -e GITHUB_TOKEN=git/github.com/alex -- gh release create v1.2.0
```

Any kind can be mapped, so a `git-credential` secret serves both git and the tooling around it.

## Hosts keycell should not handle

The helper answers nothing for a host without a secret and exits 0, so git carries on with the next helper or the prompt. Where another helper should take over, list keycell first and the other one after it; git stops at the first answer:

```
$ git config --global --add credential.helper '!keycell git-credential'
$ git config --global --add credential.helper cache
```

Note that git also hands every approved credential to every helper, so the second one stores what the prompt produced too.

## Migrating from `git-credential-store`

`~/.git-credentials` holds one `https://user:token@host` per line in plain text. Move each into the vault, then remove the file and the old helper:

```
$ printf '%s\n' "$TOKEN" | keycell store -k git-credential -a host=github.com -a username=alex git/github.com/alex
$ git config --global --unset-all credential.helper
$ git config --global credential.helper '!keycell git-credential'
$ shred -u ~/.git-credentials
```

Check with `git config --global --get-all credential.helper` that only keycell is left, and with `git config --show-origin --get-all credential.helper` that no repository or system config adds another one.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `git: 'credential-keycell' is not a git command` | The helper string lacks the leading `!`. |
| Prompted on every push, nothing in `keycell list -k git-credential` | The daemon was locked when git ran `store`. Unlock and push once more. |
| `keycell: git-credential: ambiguous match: ...` | Two secrets fit the request. Add the user name to the URL or to `credential.<url>.username`, or delete one. |
| A `path`-scoped secret is never used | `credential.useHttpPath` is not set, so git does not send the path. |
| Works in the terminal, not in an IDE | The IDE's `PATH` lacks `~/.local/bin`, or its session has no `XDG_RUNTIME_DIR`. Use an absolute path in the helper string: `'!/home/alex/.local/bin/keycell git-credential'`. |
| `keycell: git-credential: value of <name> contains a newline` | The value holds a newline git's line protocol cannot carry, e.g. from `printf 'token\n\n'`. Store it again. |

`git -c credential.helper='!keycell git-credential' credential fill` with `protocol=https`, `host=github.com` and a blank line on stdin shows exactly what git would get, without touching a remote.
